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
import shutil
import sys
import tempfile
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

from evidenceforge import __version__
from evidenceforge.generation import GenerationEngine
from evidenceforge.models.scenario import Scenario
from evidenceforge.output_targets import (
    OUTPUT_TARGET_FILENAME,
    normalize_output_target,
    write_output_target_marker,
)
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


def _path_exists_or_symlink(path: Path) -> bool:
    """Return True for existing paths and dangling symlinks."""
    return path.exists() or path.is_symlink()


def _reject_generated_sidecar_symlinks(paths: list[Path]) -> None:
    """Reject generated sidecar paths that are symlinks, including dangling ones."""
    symlinks = [path for path in paths if path.is_symlink()]
    if symlinks:
        joined = ", ".join(str(path) for path in symlinks)
        raise PermissionError(f"Refusing to write generated sidecar through symlink: {joined}")


app = typer.Typer(
    name="eforge",
    help="EvidenceForge - Generate realistic synthetic security logs for threat hunting training",
    add_completion=False,
    cls=AbbreviatedGroup,
    context_settings={"help_option_names": ["-h", "--help"]},
)
console = Console()

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


def _normalize_oob_hosts(oob_host: list[str]) -> tuple[str, ...]:
    """Normalize/validate operator-supplied --oob-host values for fail-fast CLI UX.

    Delegates the actual contract to ``adversarial_payload.normalize_oob_host`` — the single
    source of truth, which is ALSO enforced at the safety boundary (``check_payload_safety``)
    so a broad value (a bare TLD/public suffix that would allowlist a whole namespace via the
    suffix match) can never reach the allowlist regardless of caller. A value must be a concrete
    registrable domain (e.g. example.com, oast.fun, or a subdomain of one) or an IP literal.
    Shared by `generate` and `validate`. Prints a friendly error and raises
    typer.Exit(EXIT_INPUT_ERROR) on a bad value.
    """
    from evidenceforge.generation.adversarial_payload import (
        AdversarialPayloadSafetyError,
        normalize_oob_host,
    )

    normalized: list[str] = []
    for raw in oob_host:
        if not raw.strip():
            continue
        try:
            normalized.append(normalize_oob_host(raw))
        except AdversarialPayloadSafetyError as exc:
            console.print(f"[bold red]Error:[/bold red] {exc}", style="red")
            raise typer.Exit(EXIT_INPUT_ERROR) from exc
    return tuple(dict.fromkeys(normalized))


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
        validator = ScenarioValidator(scenario, oob_hosts=oob_hosts)
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
                    # Wrap in Text() (like the message above) so bracketed tokens
                    # such as "roles: [web_server]" are not parsed as Rich markup.
                    console.print(Text(f"    💡 {issue.suggestion}", style="dim"))

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
    artifacts_dir = ground_truth_dir / "artifacts"

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
        console.print(f"[dim]Format filter: generating {sorted(filtered)}[/dim]")

    console.print(f"\n[bold]Data directory:[/bold] {data_dir}")
    console.print(f"[bold]Ground truth:[/bold] {ground_truth_dir / 'GROUND_TRUTH.md'}")

    # Check for existing generated output (data/ and generated sidecars only).
    # ENVIRONMENT.md is authored by /eforge scenario, not the engine — never touch it.
    existing = []
    gt_path = ground_truth_dir / "GROUND_TRUTH.md"
    # GROUND_TRUTH.json is the canonical machine-readable companion to
    # GROUND_TRUTH.md, so it participates in overwrite detection, backup/rollback,
    # and the final listing as part of the matched output set.
    json_path = ground_truth_dir / GROUND_TRUTH_JSON_FILENAME
    manifest_path = ground_truth_dir / OBSERVATION_MANIFEST_FILENAME
    target_path = ground_truth_dir / OUTPUT_TARGET_FILENAME
    email_artifacts_path = artifacts_dir / "email"
    try:
        _reject_generated_sidecar_symlinks(
            [gt_path, json_path, manifest_path, target_path, artifacts_dir]
        )
    except PermissionError as e:
        console.print(f"[bold red]Error:[/bold red] {e}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR)

    if _path_exists_or_symlink(data_dir):
        existing.append(f"  data/           ({data_dir})")
    if _path_exists_or_symlink(gt_path):
        existing.append(f"  GROUND_TRUTH.md ({gt_path})")
    if _path_exists_or_symlink(json_path):
        existing.append(f"  {GROUND_TRUTH_JSON_FILENAME} ({json_path})")
    if _path_exists_or_symlink(manifest_path):
        existing.append(f"  {OBSERVATION_MANIFEST_FILENAME} ({manifest_path})")
    if _path_exists_or_symlink(target_path):
        existing.append(f"  {OUTPUT_TARGET_FILENAME} ({target_path})")
    if _path_exists_or_symlink(email_artifacts_path):
        existing.append(f"  artifacts/email/ ({email_artifacts_path})")

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
                output_dir=gen_data_dir,
                progress_callback=progress_callback,
                ground_truth_dir=gen_gt_dir,
                artifact_dir=gen_artifacts_dir,
                output_target=output_target,
                oob_hosts=oob_hosts,
            )
            engine.generate()
            write_output_target_marker(gen_gt_dir, output_target)

        # Transactional swap: backup old → install new → cleanup backup.
        # If any step fails (including KeyboardInterrupt), old output is
        # restored from backup. data/ and generated sidecars are always kept
        # as a matched set — partial preservation is never valid.
        if staging_dir:
            staged_gt = gen_gt_dir / "GROUND_TRUTH.md"
            staged_json = gen_gt_dir / GROUND_TRUTH_JSON_FILENAME
            staged_manifest = gen_gt_dir / OBSERVATION_MANIFEST_FILENAME
            staged_target = gen_gt_dir / OUTPUT_TARGET_FILENAME
            staged_artifacts = gen_artifacts_dir
            if not gen_data_dir.exists():
                raise RuntimeError("Staged data/ directory missing after generation")
            if not staged_gt.exists():
                raise RuntimeError("Staged GROUND_TRUTH.md missing after generation")
            if not staged_json.exists():
                raise RuntimeError(f"Staged {GROUND_TRUTH_JSON_FILENAME} missing after generation")
            if not staged_manifest.exists():
                raise RuntimeError(
                    f"Staged {OBSERVATION_MANIFEST_FILENAME} missing after generation"
                )
            if not staged_target.exists():
                raise RuntimeError(f"Staged {OUTPUT_TARGET_FILENAME} missing after generation")

            # Clean up stale rollback dirs from prior killed runs
            for stale in ground_truth_dir.glob(".eforge_rollback_*"):
                logger.warning("Cleaning stale rollback directory: %s", stale)
                shutil.rmtree(stale, ignore_errors=True)

            rollback_dir = Path(tempfile.mkdtemp(prefix=".eforge_rollback_", dir=ground_truth_dir))
            swap_succeeded = False
            try:
                # Step 1: Backup old output
                if data_dir.exists():
                    data_dir.rename(rollback_dir / "data")
                if gt_path.exists():
                    gt_path.rename(rollback_dir / "GROUND_TRUTH.md")
                if json_path.exists():
                    json_path.rename(rollback_dir / GROUND_TRUTH_JSON_FILENAME)
                if manifest_path.exists():
                    manifest_path.rename(rollback_dir / OBSERVATION_MANIFEST_FILENAME)
                if _path_exists_or_symlink(target_path):
                    target_path.rename(rollback_dir / OUTPUT_TARGET_FILENAME)
                if artifacts_dir.exists():
                    artifacts_dir.rename(rollback_dir / "artifacts")

                # Step 2: Install new output.
                gen_data_dir.rename(data_dir)
                staged_gt.rename(gt_path)
                staged_json.rename(json_path)
                if staged_manifest.exists():
                    staged_manifest.rename(manifest_path)
                if staged_target.exists():
                    staged_target.rename(target_path)
                if staged_artifacts.exists():
                    staged_artifacts.rename(artifacts_dir)
                swap_succeeded = True

            except BaseException:
                # Rollback: remove partially-installed new output, restore old.
                # Strip whatever new artifact is currently installed UNCONDITIONALLY
                # — whether a backup of it exists is irrelevant to whether the new
                # one must go before restore. (A partial prior state, e.g. data/ but
                # no GROUND_TRUTH.md, must not leave a new GT.md orphaned over
                # restored old data/ — that breaks the matched-set invariant.)
                try:
                    if data_dir.exists():
                        shutil.rmtree(data_dir)
                    if gt_path.exists():
                        gt_path.unlink()
                    if json_path.exists():
                        json_path.unlink()
                    if manifest_path.exists():
                        manifest_path.unlink()
                    if artifacts_dir.exists():
                        shutil.rmtree(artifacts_dir)
                    if _path_exists_or_symlink(target_path):
                        target_path.unlink()
                    if (rollback_dir / "data").exists():
                        (rollback_dir / "data").rename(data_dir)
                    if (rollback_dir / "GROUND_TRUTH.md").exists():
                        (rollback_dir / "GROUND_TRUTH.md").rename(gt_path)
                    rollback_json = rollback_dir / GROUND_TRUTH_JSON_FILENAME
                    if rollback_json.exists():
                        rollback_json.rename(json_path)
                    rollback_manifest = rollback_dir / OBSERVATION_MANIFEST_FILENAME
                    if rollback_manifest.exists():
                        rollback_manifest.rename(manifest_path)
                    rollback_artifacts = rollback_dir / "artifacts"
                    if rollback_artifacts.exists():
                        rollback_artifacts.rename(artifacts_dir)
                    rollback_target = rollback_dir / OUTPUT_TARGET_FILENAME
                    if rollback_target.exists():
                        rollback_target.rename(target_path)
                except Exception:
                    logger.error("Rollback failed — old output may be in: %s", rollback_dir)
                raise
            finally:
                if swap_succeeded:
                    shutil.rmtree(rollback_dir, ignore_errors=True)
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
                    OUTPUT_TARGET_FILENAME,
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
    oob_host: list[str] = typer.Option(
        [],
        "--oob-host",
        help="Allowlist an operator-controlled out-of-band host (concrete registrable "
        "domain or IP literal) when validating a scenario whose adversarial_payload uses a "
        "literal `value:` pointing at that host — parity with `generate --oob-host`, so "
        "'validate before generate' stays reliable for live-callback scenarios. Validation "
        "only: no callback is ever made. Repeatable.",
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
    console.print("[bold blue]EvidenceForge Scenario Validator[/bold blue]")
    console.print(f"Scenario: {scenario_file}\n")

    # Normalize/validate --oob-host the same way `generate` does, so a literal OOB payload
    # validates identically here (fail fast on a bad value before loading the scenario).
    oob_hosts: tuple[str, ...] = _normalize_oob_hosts(oob_host)

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
    validator = ScenarioValidator(scenario, oob_hosts=oob_hosts)
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
                # Wrap in Text() so bracketed tokens (e.g. "roles: [web_server]")
                # are not parsed as Rich markup and dropped.
                console.print(Text(f"    💡 {issue.suggestion}", style="dim"))

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
    real_parsers: bool = typer.Option(
        False,
        "--real-parsers",
        help="[Reserved] Evaluate using real downstream parser binaries (not yet implemented).",
        is_flag=True,
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
    if real_parsers:
        console.print("[yellow]--real-parsers: real parser backend not yet implemented.[/yellow]")
        return

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
    agent: str = typer.Option(
        "claude",
        "--agent",
        help="Agent to install skills for: claude or codex",
    ),
    global_install: bool = typer.Option(
        False, "--global", help="Install to ~/.claude/commands/ (global)"
    ),
) -> None:
    """Install EvidenceForge skills for supported agent workflows.

    By default, installs Claude Code slash commands to .claude/commands/ in the
    current directory. Use --global with Claude installs to install to
    ~/.claude/commands/. Use --agent codex to install Codex skills to
    ~/.codex/skills/.

    Existing installations are updated: new files are copied, changed files
    are overwritten, and stale files from previous versions are removed.
    """
    from evidenceforge.cli.install_skills import install_codex_skills, install_skills

    normalized_agent = agent.lower()
    if normalized_agent not in {"claude", "codex"}:
        console.print(
            f"[bold red]Error:[/bold red] Unknown agent '{agent}'. Use 'claude' or 'codex'.",
            style="red",
        )
        raise typer.Exit(EXIT_INPUT_ERROR)

    if normalized_agent == "codex" and global_install:
        console.print(
            "[bold red]Error:[/bold red] --global is only valid for Claude installs. "
            "Codex skills install to ~/.codex/skills/.",
            style="red",
        )
        raise typer.Exit(EXIT_INPUT_ERROR)

    if normalized_agent == "codex":
        target_dir = Path.home() / ".codex" / "skills"
        scope = "user"
        install_func = install_codex_skills
    elif global_install:
        target_dir = Path.home() / ".claude" / "commands"
        scope = "global"
        install_func = install_skills
    else:
        target_dir = Path.cwd() / ".claude" / "commands"
        scope = "project"
        install_func = install_skills

    console.print(
        f"[bold blue]Installing EvidenceForge skills for {normalized_agent} ({scope})[/bold blue]"
    )
    console.print(f"Target: {target_dir}\n")

    try:
        installed, removed = install_func(target_dir)
    except FileNotFoundError as e:
        console.print(f"[bold red]Error:[/bold red] {e}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR)
    except PermissionError as e:
        console.print(f"[bold red]Error:[/bold red] {e}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR)

    if installed:
        console.print(f"[green]✓[/green] Installed {len(installed)} files:")
        for f in installed:
            if normalized_agent == "claude":
                console.print(f"  eforge/{f}")
            else:
                console.print(f"  {f}")

    if removed:
        console.print(f"\n[yellow]Removed {len(removed)} stale files:[/yellow]")
        for f in removed:
            if normalized_agent == "claude":
                console.print(f"  eforge/{f}", style="dim")
            else:
                console.print(f"  {f}", style="dim")

    if normalized_agent == "claude":
        console.print(f"\n[bold green]✓ Skills installed to {target_dir / 'eforge'}[/bold green]")
        console.print(
            "Use /eforge scenario, /eforge generate, /eforge validate, /eforge evaluate, or /eforge config."
        )
    else:
        console.print(f"\n[bold green]✓ Skills installed to {target_dir}[/bold green]")
        console.print(
            "Use the eforge-scenario, eforge-generate, eforge-validate, "
            "eforge-evaluate, or eforge-config skills."
        )


@app.command()
def info(
    field: str = typer.Argument(
        None, help="Dot-path to a specific field (e.g., paths.activity, overlay.exists, personas)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON for machine parsing"),
    list_fields_flag: bool = typer.Option(
        False, "--fields", help="List all valid dot-path field names"
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
        format_json,
        gather_info,
        list_fields,
        resolve_field,
    )

    try:
        data = gather_info(field=field)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Failed to gather info: {e}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR)

    if list_fields_flag and field:
        console.print(
            "[bold red]Error:[/bold red] Cannot use --fields with a field argument. "
            "Use 'eforge info --fields' to list fields, or 'eforge info <field>' to get a value.",
            style="red",
        )
        raise typer.Exit(EXIT_INPUT_ERROR)

    if list_fields_flag:
        fields = list_fields(data)
        if json_output:
            import json

            print(json.dumps({name: desc for name, desc in fields}, indent=2))
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
            console.print(f"[bold red]Error:[/bold red] Unknown field: {field}", style="red")
            raise typer.Exit(EXIT_INPUT_ERROR)
        if isinstance(value, list):
            print("\n".join(str(v) for v in value))
        elif isinstance(value, dict):
            import json

            print(json.dumps(value))
        else:
            print(value)
    elif json_output:
        # JSON goes to stdout without Rich formatting
        print(format_json(data))
    else:
        console.print(format_human_readable(data))


@app.command("validate-config")
def validate_config_cmd(
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Validate config files for integrity and cross-reference consistency.

    Runs 27 checks across all config YAML files (activity, personas, formats,
    evaluation) including any overlay customizations. Reports errors, warnings,
    and info items.

    Exit codes:
    - 0: All checks passed (may include warnings/info)
    - 2: Errors found
    """
    from evidenceforge.cli.validate_config import validate_config

    status_console = Console(stderr=True) if json_output else console
    status_console.print("[bold blue]EvidenceForge Config Validator[/bold blue]")

    try:
        result = validate_config()
    except Exception as e:
        status_console.print(f"[bold red]Error:[/bold red] Validation failed: {e}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR)

    if json_output:
        import json

        output = {
            "files_checked": result.files_checked,
            "errors": [{"file": i.file, "message": i.message} for i in result.errors],
            "warnings": [{"file": i.file, "message": i.message} for i in result.warnings],
            "info": [{"file": i.file, "message": i.message} for i in result.infos],
        }
        # JSON mode: only JSON on stdout, exit non-zero on errors
        print(json.dumps(output, indent=2))
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
