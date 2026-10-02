# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Predict generation resources without starting a run."""

from pathlib import Path

import typer
from rich.console import Console

from evidenceforge.config.context import ConfigurationContextError, select_context
from evidenceforge.resources import predict_resources

resources_app = typer.Typer(help="Predict generation memory and disk requirements without a run.")
console = Console()


def _size(value: int) -> str:
    return f"{value / (1024**2):,.1f} MiB"


@resources_app.command("predict")
def predict(
    scenario_file: Path = typer.Argument(..., help="Authored or authoritative scenario YAML."),
    project_root: Path | None = typer.Option(None, help="Workspace supplying packs and overlays."),
    destination: Path | None = typer.Option(
        None, help="Output parent to check disk capacity; nothing is created. Defaults to runs/."
    ),
    checkpoint_hours: int = typer.Option(
        24, min=0, help="Simulated hours between checkpoints; 0 disables."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit the versioned prediction contract."
    ),
    context: Path | None = typer.Option(
        None, "--context", help="Explicit configuration context YAML."
    ),
) -> None:
    """Estimate resource ranges. Run validate separately to check correctness and safety."""
    try:
        root = select_context(project_root, context).project_root
    except ConfigurationContextError as exc:
        from evidenceforge.resources import ResourcePrediction

        result = ResourcePrediction(destination=destination or Path.cwd() / "runs", error=str(exc))
        if json_output:
            print(result.model_dump_json(indent=2))
        else:
            console.print(f"[red]Prediction unavailable:[/red] {result.error}")
        raise typer.Exit(1) from exc
    result = predict_resources(
        scenario_file,
        destination or root / "runs",
        project_root=project_root,
        checkpoint_hours=checkpoint_hours,
        context=context,
    )
    if json_output:
        print(result.model_dump_json(indent=2))
    elif result.forecast:
        forecast = result.forecast
        console.print(f"[bold]Resource forecast: {result.scenario_name}[/bold]")
        console.print(f"  Estimated generated data: {_size(forecast.final_output.expected_bytes)}")
        console.print(f"  Estimated peak memory: {_size(forecast.memory.expected_bytes)}")
        console.print(
            f"  Estimated peak disk including checkpoints: {_size(forecast.disk.expected_bytes)}"
        )
        console.print(f"  Available disk: {_size(forecast.snapshot.free_disk_bytes)}")
        for pressure in forecast.pressures:
            console.print(
                f"  [yellow]{pressure.level.title()} {pressure.resource} pressure[/yellow]"
            )
        console.print("  Estimates may differ from actual use. This does not replace validation.")
    else:
        console.print(f"[red]Prediction unavailable:[/red] {result.error}")
    if not result.available:
        raise typer.Exit(1)
