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

import logging
import sys
from pathlib import Path

import click
import typer
from pydantic import ValidationError
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

from evidenceforge.generation import GenerationEngine
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils import load_yaml


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
app = typer.Typer(
    name="eforge",
    help="EvidenceForge - Generate realistic synthetic security logs for threat hunting training",
    add_completion=False,
    cls=AbbreviatedGroup,
)
console = Console()

# Exit codes (per TODO.md specification)
EXIT_SUCCESS = 0
EXIT_INPUT_ERROR = 1
EXIT_SCHEMA_VALIDATION = 2
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


@app.command()
def generate(
    scenario_file: Path = typer.Argument(
        ...,
        help="Path to scenario YAML file",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output directory for generated logs (overrides scenario setting)",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Enable verbose (INFO level) logging"
    ),
    debug: bool = typer.Option(False, "--debug", "-d", help="Enable debug (DEBUG level) logging"),
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
    setup_logging(verbose, debug)
    logger = logging.getLogger(__name__)

    console.print("[bold blue]EvidenceForge Log Generator[/bold blue]")
    console.print(f"Scenario: {scenario_file}")

    # Load and validate scenario
    try:
        console.print("\n[bold]Loading scenario...[/bold]")
        scenario_data = load_yaml(scenario_file)
        from evidenceforge.utils.personas import merge_builtin_personas

        scenario_data = merge_builtin_personas(scenario_data)
        scenario = Scenario(**scenario_data)
        console.print(f"[green]✓[/green] Loaded scenario: {scenario.name}")
        console.print(f"  Description: {scenario.description}")
        console.print(f"  Users: {len(scenario.environment.users)}")
        console.print(f"  Systems: {len(scenario.environment.systems)}")
        if scenario.storyline:
            console.print(f"  Storyline events: {len(scenario.storyline)}")

        # Cross-reference validation (Phase 1.9)
        from evidenceforge.validation import ScenarioValidator

        console.print("\n[bold]Validating cross-references...[/bold]")
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        if issues:
            console.print(f"\n[yellow]Found {len(issues)} validation issue(s):[/yellow]")
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
                    console.print(f"    💡 {issue.suggestion}", style="dim")

            if validator.has_errors():
                console.print(
                    "\n[bold red]Validation failed with errors. Cannot proceed with generation.[/bold red]"
                )
                raise typer.Exit(EXIT_SCHEMA_VALIDATION)
            else:
                console.print("\n[yellow]Warnings found but proceeding with generation...[/yellow]")
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

    except ValidationError as e:
        console.print("[bold red]Error:[/bold red] Schema validation failed", style="red")
        console.print("\nValidation errors:")
        for error in e.errors():
            field = " -> ".join(str(loc) for loc in error["loc"])
            console.print(f"  • {field}: {error['msg']}", style="red")
        raise typer.Exit(EXIT_SCHEMA_VALIDATION)

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Failed to load scenario: {e}", style="red")
        if verbose or debug:
            console.print_exception()
        raise typer.Exit(EXIT_INPUT_ERROR)

    # Determine output directory
    if output:
        # Explicit --output flag: logs in data/ subdirectory, ground truth at root
        data_dir = output / "data"
        ground_truth_dir = output
    else:
        # Default: derive from scenario file location
        # scenarios/<name>/scenario.yaml → data goes to scenarios/<name>/data/
        scenario_dir = scenario_file.parent
        data_dir = scenario_dir / "data"
        ground_truth_dir = scenario_dir

    console.print(f"\n[bold]Data directory:[/bold] {data_dir}")
    console.print(f"[bold]Ground truth:[/bold] {ground_truth_dir / 'GROUND_TRUTH.md'}")

    # Clear previous data on re-generation
    if data_dir.exists():
        import shutil

        shutil.rmtree(data_dir)
        console.print("[dim]Cleared previous data[/dim]")

    # Generate logs
    try:
        console.print("\n[bold]Starting log generation...[/bold]")

        # Create progress display with Rich
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
            transient=False,  # Keep progress bars visible after completion
        ) as progress:
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
                output_dir=data_dir,
                progress_callback=progress_callback,
                ground_truth_dir=ground_truth_dir,
            )
            engine.generate()

        console.print("\n[bold green]✓ Generation complete![/bold green]")
        console.print("\nGenerated files:")
        console.print(f"  Scenario directory: {ground_truth_dir}")

        # List files in scenario root (GROUND_TRUTH.md)
        if ground_truth_dir.exists():
            for file in sorted(ground_truth_dir.iterdir()):
                if file.is_file() and file.name == "GROUND_TRUTH.md":
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

        # Success - exit normally
        return

    except KeyboardInterrupt:
        console.print("\n[bold yellow]Interrupted by user (Ctrl+C)[/bold yellow]")
        logger.info("Generation interrupted by user")
        raise typer.Exit(EXIT_SIGINT)

    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] Generation failed: {e}", style="red")
        if verbose or debug:
            console.print_exception()
        logger.exception("Generation failed")
        raise typer.Exit(EXIT_GENERATION_ERROR)


@app.command()
def validate(
    scenario_file: Path = typer.Argument(
        ...,
        help="Path to scenario YAML file",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
) -> None:
    """Validate a scenario file for schema correctness and cross-reference integrity.

    Checks YAML structure, Pydantic schema compliance, and internal consistency
    (user/system/persona references, network topology, etc.) without generating logs.

    Exit codes:
    - 0: Validation passed
    - 1: YAML parse error or file I/O error
    - 2: Schema validation or cross-reference error
    """
    console.print("[bold blue]EvidenceForge Scenario Validator[/bold blue]")
    console.print(f"Scenario: {scenario_file}\n")

    # Step 1: Load and parse YAML
    try:
        scenario_data = load_yaml(scenario_file)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Failed to parse YAML: {e}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR)

    # Step 1.5: Merge pre-built personas
    from evidenceforge.utils.personas import merge_builtin_personas

    scenario_data = merge_builtin_personas(scenario_data)

    # Step 2: Pydantic schema validation
    try:
        scenario = Scenario(**scenario_data)
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
    except ValidationError as e:
        console.print("[bold red]Schema validation failed:[/bold red]")
        for error in e.errors():
            loc = " → ".join(str(x) for x in error["loc"])
            console.print(f"  [red]✗ {loc}[/red]")
            console.print(f"    {error['msg']}", style="red")
        raise typer.Exit(EXIT_SCHEMA_VALIDATION)

    # Step 3: Cross-reference validation
    from evidenceforge.validation import ScenarioValidator

    console.print("\n[bold]Validating cross-references...[/bold]")
    validator = ScenarioValidator(scenario)
    issues = validator.validate()

    if issues:
        console.print(f"\n[yellow]Found {len(issues)} validation issue(s):[/yellow]")
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
                console.print(f"    💡 {issue.suggestion}", style="dim")

        if validator.has_errors():
            console.print("\n[bold red]Validation failed with errors.[/bold red]")
            raise typer.Exit(EXIT_SCHEMA_VALIDATION)
        else:
            console.print("\n[yellow]Warnings found but scenario is valid.[/yellow]")
    else:
        console.print("[green]✓[/green] All cross-references valid")

    console.print("\n[bold green]✓ Scenario is valid.[/bold green]")


@app.command("eval")
def eval_cmd(
    output_dir: Path = typer.Argument(
        ...,
        help="Directory containing generated log files",
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
    ),
    scenario_file: Path = typer.Option(
        ...,
        "--scenario",
        "-s",
        help="Path to the scenario YAML used for generation",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
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
) -> None:
    """Evaluate a generated dataset for quality across multiple dimensions.

    Reads generated log files and the original scenario, runs deterministic
    and statistical quality checks, and produces a quality report.

    Exit codes:
    - 0: Evaluation completed (check report for pass/fail)
    - 1: Input error (file not found, invalid path)
    - 2: Schema validation error in scenario
    - 22: Evaluation engine error
    """
    setup_logging(verbose)

    # Use stderr for status messages in JSON mode to keep stdout clean
    status_console = Console(stderr=True) if output_format == "json" else console

    status_console.print("[bold blue]EvidenceForge Data Quality Evaluation[/bold blue]")
    status_console.print(f"Output directory: {output_dir}")
    status_console.print(f"Scenario: {scenario_file}")

    # Load and validate scenario
    try:
        scenario_data = load_yaml(scenario_file)
        from evidenceforge.utils.personas import merge_builtin_personas

        scenario_data = merge_builtin_personas(scenario_data)
        scenario = Scenario(**scenario_data)
        status_console.print(f"[green]✓[/green] Loaded scenario: {scenario.name}")
    except ValidationError as e:
        status_console.print(
            "[bold red]Error:[/bold red] Scenario schema validation failed",
            style="red",
        )
        for error in e.errors():
            field = " -> ".join(str(loc) for loc in error["loc"])
            status_console.print(f"  • {field}: {error['msg']}", style="red")
        raise typer.Exit(EXIT_SCHEMA_VALIDATION)
    except Exception as e:
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
                output_dir=output_dir,
                scenario=scenario,
                verbose=verbose,
                progress_callback=eval_progress,
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
    global_install: bool = typer.Option(
        False, "--global", help="Install to ~/.claude/commands/ (global)"
    ),
) -> None:
    """Install EvidenceForge Claude Code skills as custom slash commands.

    Copies skill files, persona library, and reference docs to the Claude Code
    commands directory. By default installs to .claude/commands/ in the current
    directory (project scope). Use --global to install to ~/.claude/commands/.

    Existing installations are updated: new files are copied, changed files
    are overwritten, and stale files from previous versions are removed.
    """
    from evidenceforge.cli.install_skills import install_skills

    if global_install:
        target_dir = Path.home() / ".claude" / "commands"
        scope = "global"
    else:
        target_dir = Path.cwd() / ".claude" / "commands"
        scope = "project"

    console.print(f"[bold blue]Installing EvidenceForge skills ({scope})[/bold blue]")
    console.print(f"Target: {target_dir}\n")

    try:
        installed, removed = install_skills(target_dir)
    except FileNotFoundError as e:
        console.print(f"[bold red]Error:[/bold red] {e}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR)
    except PermissionError as e:
        console.print(f"[bold red]Error:[/bold red] {e}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR)

    if installed:
        console.print(f"[green]✓[/green] Installed {len(installed)} files:")
        for f in installed:
            console.print(f"  eforge/{f}")

    if removed:
        console.print(f"\n[yellow]Removed {len(removed)} stale files:[/yellow]")
        for f in removed:
            console.print(f"  eforge/{f}", style="dim")

    console.print(f"\n[bold green]✓ Skills installed to {target_dir / 'eforge'}[/bold green]")


@app.command()
def info(
    json_output: bool = typer.Option(False, "--json", help="Output as JSON for machine parsing"),
) -> None:
    """Show EvidenceForge installation info: version, config paths, available data.

    Displays version, install type, config file paths, and inventories of
    available personas, formats, DNS tags, application IDs, and system roles.
    Use --json for machine-readable output (used by Claude Code skills).
    """
    from evidenceforge.cli.info import format_human_readable, format_json, gather_info

    try:
        data = gather_info()
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Failed to gather info: {e}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR)

    if json_output:
        # JSON goes to stdout without Rich formatting
        print(format_json(data))
    else:
        console.print(format_human_readable(data))


@app.command()
def version() -> None:
    """Show version information."""
    console.print("EvidenceForge v0.1.0")
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
