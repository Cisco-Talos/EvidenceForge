"""Operational CLI commands for incremental generation checkpoints."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from evidenceforge.generation.checkpoints.control import request_suspension
from evidenceforge.generation.checkpoints.errors import CheckpointError
from evidenceforge.generation.checkpoints.status import (
    CheckpointStatusReport,
    checkpoint_bundle_root_hint,
    inspect_checkpoint,
)
from evidenceforge.generation.checkpoints.store import IncrementalCheckpointStore

checkpoint_app = typer.Typer(
    help="Inspect and control checkpoint-enabled generation.",
    no_args_is_help=True,
)
console = Console()


def _format_bytes(value: int) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    amount = float(value)
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:,.0f} {unit}" if unit == "B" else f"{amount:,.2f} {unit}"
        amount /= 1024
    return f"{value:,} B"  # pragma: no cover - loop always returns


def _render_status(report: CheckpointStatusReport, *, verbose: bool) -> None:
    state_style = {
        "active": "cyan",
        "resumable": "green",
        "completed": "green",
        "absent": "yellow",
        "invalid": "red",
    }[report.state]
    state_label = report.state
    if report.state == "absent":
        state_label = "no checkpoints found"
    elif report.state == "active" and report.simulated_hour is None:
        state_label = "active — no checkpoint yet"
    console.print(f"[bold]Checkpoint state:[/bold] [{state_style}]{state_label}[/{state_style}]")
    if report.state == "absent":
        for warning in report.warnings:
            console.print(f"[yellow]Hint:[/yellow] {warning}")
        return
    if report.simulated_hour is not None:
        console.print(
            f"[bold]Recovery point:[/bold] simulated hour {report.simulated_hour} ({report.phase})"
        )
    if report.checkpoint_hours is not None:
        console.print(f"[bold]Cadence:[/bold] every {report.checkpoint_hours} simulated hours")
    if report.integrity == "pending" and report.simulated_hour is None:
        console.print("[bold]Validation:[/bold] waiting for the first checkpoint")
    else:
        console.print(
            f"[bold]Validation:[/bold] integrity {report.integrity}; "
            f"runtime compatibility {report.compatibility}"
        )
    if report.suspended:
        console.print("[bold yellow]Generation is intentionally suspended.[/bold yellow]")
    elif report.suspension_requested:
        console.print(
            "[yellow]Suspension requested; generation is finishing its current simulated hour.[/yellow]"
        )
    storage = report.storage
    console.print(
        f"[bold]Storage:[/bold] {_format_bytes(storage.generated_bytes)} generated + "
        f"{_format_bytes(storage.recovery_overhead_bytes)} recovery overhead"
    )
    console.print(
        f"[bold]Total known managed working footprint:[/bold] "
        f"{_format_bytes(storage.total_managed_bytes)}"
    )
    if report.resume_command is not None:
        console.print(f"[bold]Resume:[/bold] {report.resume_command}")
    for warning in report.warnings:
        console.print(f"[yellow]Warning:[/yellow] {warning}")
    for error in report.errors:
        console.print(f"[bold red]Error:[/bold red] {error}")
    if not verbose:
        return

    console.print("\n[bold]Storage diagnostics[/bold]")
    storage_table = Table(show_header=False, box=None)
    storage_table.add_column("Item", style="cyan")
    storage_table.add_column("Value", justify="right")
    diagnostic_sizes = (
        ("Staged/current generated data", storage.generated_bytes),
        ("Checkpoint recovery objects", storage.checkpoint_bytes),
        ("Prior published bundle", storage.prior_bundle_bytes),
        ("Available disk", storage.available_bytes),
    )
    for label, value in diagnostic_sizes:
        if value is None:
            continue
        storage_table.add_row(label, _format_bytes(value))
    storage_table.add_row("Managed files", f"{storage.managed_file_count:,}")
    storage_table.add_row("Unrelated root entries excluded", str(storage.unrelated_entry_count))
    console.print(storage_table)

    if report.recovery_points:
        console.print("\n[bold]Recovery generations[/bold]")
        table = Table("Role", "Sequence", "Health", "Cursor", "Detail")
        for point in report.recovery_points:
            cursor = (
                "—"
                if point.simulated_hour is None
                else f"hour {point.simulated_hour} ({point.phase})"
            )
            table.add_row(
                point.role,
                str(point.sequence),
                "valid" if point.valid else "invalid",
                cursor,
                point.error or "",
            )
        console.print(table)

    console.print("\n[bold]Developer diagnostics[/bold]")
    for key, value in sorted(report.diagnostics.items()):
        rendered = (
            json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
        )
        console.print(f"  [cyan]{key}:[/cyan] {rendered}")


@checkpoint_app.command("status")
def checkpoint_status(
    directory: Path = typer.Argument(..., help="Generation output root to inspect."),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show recovery generations and developer diagnostics.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit the complete stable status report as JSON.",
    ),
) -> None:
    """Thoroughly validate checkpoint recovery and report managed storage."""

    if json_output:
        report = inspect_checkpoint(directory)
        typer.echo(json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True))
    else:
        with console.status("Validating checkpoint recovery and managed storage..."):
            report = inspect_checkpoint(directory)
        _render_status(report, verbose=verbose)
    if report.state in {"invalid", "absent"}:
        raise typer.Exit(1)


@checkpoint_app.command("suspend")
def checkpoint_suspend(
    directory: Path = typer.Argument(..., help="Output root owned by the active generation."),
) -> None:
    """Request a safe checkpoint and stop after the current simulated hour."""

    console.print(
        "[bold yellow]Suspension is not immediate.[/bold yellow] The generator will stop at the "
        "end of its current simulated hour, after a safe recovery checkpoint is committed."
    )
    suggested_root = checkpoint_bundle_root_hint(directory)
    if suggested_root is not None:
        console.print(
            "[bold red]Error:[/bold red] No checkpoint workspace was found at that path. "
            "It appears to be the generated data directory; use the bundle root instead: "
            f"eforge checkpoint suspend {suggested_root}"
        )
        raise typer.Exit(1)
    try:
        request = request_suspension(IncrementalCheckpointStore(directory))
    except CheckpointError as error:
        console.print(f"[bold red]Error:[/bold red] {error}")
        raise typer.Exit(1) from None
    console.print(
        f"[green]✓[/green] Suspension request accepted ({request.request_id[:12]}). "
        "The generation process is still running."
    )


__all__ = ["checkpoint_app", "checkpoint_status", "checkpoint_suspend"]
