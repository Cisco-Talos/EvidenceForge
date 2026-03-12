"""CLI commands for EvidenceForge log generator.

This module implements the command-line interface using Typer.
Provides commands for initialization, log generation, and validation.
"""

import logging
import sys
from pathlib import Path
from typing import Optional

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.logging import RichHandler

from log_generator.generation import GenerationEngine
from log_generator.models.scenario import Scenario
from log_generator.utils import load_yaml

# Initialize Typer app and Rich console
app = typer.Typer(
    name="forge",
    help="EvidenceForge - Generate realistic synthetic security logs for threat hunting training",
    add_completion=False,
)
console = Console()

# Exit codes (per TODO.md specification)
EXIT_SUCCESS = 0
EXIT_INPUT_ERROR = 1
EXIT_SCHEMA_VALIDATION = 2
EXIT_GENERATION_ERROR = 21
EXIT_SIGINT = 130


def setup_logging(verbose: bool = False) -> None:
    """Configure logging with Rich handler.

    Args:
        verbose: Enable debug logging if True
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, rich_tracebacks=True)]
    )


@app.command()
def init(
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite existing config.yaml if it exists"
    )
) -> None:
    """Initialize EvidenceForge by creating config.yaml from template.

    Copies config.example.yaml to config.yaml in the current directory.
    """
    console.print("[bold blue]EvidenceForge Initialization[/bold blue]")

    # Check if config.example.yaml exists
    example_config = Path("config.example.yaml")
    if not example_config.exists():
        console.print(
            "[bold red]Error:[/bold red] config.example.yaml not found in current directory",
            style="red"
        )
        console.print(
            "Please run this command from the project root directory or create config.example.yaml"
        )
        raise typer.Exit(EXIT_INPUT_ERROR)

    # Check if config.yaml already exists
    target_config = Path("config.yaml")
    if target_config.exists() and not force:
        console.print(
            "[bold yellow]Warning:[/bold yellow] config.yaml already exists",
            style="yellow"
        )
        console.print("Use --force to overwrite, or edit config.yaml manually")
        raise typer.Exit(EXIT_SUCCESS)

    # Copy config.example.yaml to config.yaml
    try:
        content = example_config.read_text()
        target_config.write_text(content)
        console.print(
            f"[bold green]✓[/bold green] Created config.yaml from {example_config}",
            style="green"
        )
        console.print("\nNext steps:")
        console.print("1. Edit config.yaml to configure AWS credentials and output settings")
        console.print("2. Run 'forge generate <scenario.yaml>' to generate logs")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Failed to create config.yaml: {e}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR)


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
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output directory for generated logs (overrides scenario setting)",
    ),
    config: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to configuration file (default: config.yaml)",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose logging"
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
    setup_logging(verbose)
    logger = logging.getLogger(__name__)

    console.print("[bold blue]EvidenceForge Log Generator[/bold blue]")
    console.print(f"Scenario: {scenario_file}")

    # Load and validate scenario
    try:
        console.print("\n[bold]Loading scenario...[/bold]")
        scenario_data = load_yaml(scenario_file)
        scenario = Scenario(**scenario_data)
        console.print(f"[green]✓[/green] Loaded scenario: {scenario.name}")
        console.print(f"  Description: {scenario.description}")
        console.print(f"  Users: {len(scenario.environment.users)}")
        console.print(f"  Systems: {len(scenario.environment.systems)}")
        if scenario.storyline:
            console.print(f"  Storyline events: {len(scenario.storyline)}")

    except FileNotFoundError:
        console.print(
            f"[bold red]Error:[/bold red] Scenario file not found: {scenario_file}",
            style="red"
        )
        raise typer.Exit(EXIT_INPUT_ERROR)

    except ValidationError as e:
        console.print(
            "[bold red]Error:[/bold red] Schema validation failed",
            style="red"
        )
        console.print("\nValidation errors:")
        for error in e.errors():
            field = " -> ".join(str(loc) for loc in error['loc'])
            console.print(f"  • {field}: {error['msg']}", style="red")
        raise typer.Exit(EXIT_SCHEMA_VALIDATION)

    except Exception as e:
        console.print(
            f"[bold red]Error:[/bold red] Failed to load scenario: {e}",
            style="red"
        )
        if verbose:
            console.print_exception()
        raise typer.Exit(EXIT_INPUT_ERROR)

    # Determine output directory
    if output:
        output_dir = output
    elif scenario.output.destination:
        output_dir = Path(scenario.output.destination)
    else:
        output_dir = Path("./output")

    # Create timestamped subdirectory
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = output_dir / f"{scenario.name}-{timestamp}"

    console.print(f"\n[bold]Output directory:[/bold] {output_dir}")

    # Generate logs
    try:
        console.print("\n[bold]Starting log generation...[/bold]")

        engine = GenerationEngine(scenario=scenario, output_dir=output_dir)
        engine.generate()

        console.print("\n[bold green]✓ Generation complete![/bold green]")
        console.print(f"\nGenerated logs:")
        console.print(f"  Directory: {output_dir}")

        # List generated files
        if output_dir.exists():
            for file in sorted(output_dir.iterdir()):
                if file.is_file():
                    size = file.stat().st_size
                    size_str = f"{size:,} bytes" if size < 1024 else f"{size / 1024:.1f} KB"
                    console.print(f"  • {file.name} ({size_str})")

        # Success - exit normally
        return

    except KeyboardInterrupt:
        console.print("\n[bold yellow]Interrupted by user (Ctrl+C)[/bold yellow]")
        logger.info("Generation interrupted by user")
        raise typer.Exit(EXIT_SIGINT)

    except Exception as e:
        console.print(
            f"\n[bold red]Error:[/bold red] Generation failed: {e}",
            style="red"
        )
        if verbose:
            console.print_exception()
        logger.exception("Generation failed")
        raise typer.Exit(EXIT_GENERATION_ERROR)


@app.command()
def version() -> None:
    """Show version information."""
    console.print("EvidenceForge v0.1.0 (Phase 1 MVP)")
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
