"""Report formatting for evaluation results.

Supports Rich text (terminal) and JSON output formats.
"""

from rich.console import Console

from evidenceforge.evaluation.models import QualityReport


def format_text_report(report: QualityReport, console: Console, verbose: bool = False) -> None:
    """Print a formatted quality report to the Rich console."""
    console.print()
    console.print("[bold]=== EvidenceForge Data Quality Report ===[/bold]")
    console.print(f"Scenario: {report.scenario_name}")
    console.print(f"Evaluated: {report.evaluated_at.strftime('%Y-%m-%dT%H:%M:%SZ')}")

    # Source summary
    source_parts = ", ".join(
        f"{name}: {count:,}" for name, count in sorted(report.source_counts.items())
    )
    console.print(
        f"Total records: {report.total_records:,} across {len(report.source_counts)} sources"
    )
    if verbose and source_parts:
        console.print(f"  ({source_parts})")

    console.print()

    # Overall score
    if report.overall_score is not None:
        score_color = _score_color(report.overall_score)
        console.print(
            f"[bold]Overall Quality Score:[/bold] "
            f"[{score_color}]{report.overall_score:.0f}/100[/{score_color}]"
        )
    else:
        console.print(
            "[bold]Overall Quality Score:[/bold] [dim]N/A (insufficient dimensions)[/dim]"
        )

    console.print()

    # Dimension scores table
    console.print("[bold]Dimension Scores:[/bold]")
    for dim in report.dimensions:
        if dim.score is not None:
            color = _score_color(dim.score)
            console.print(
                f"  {dim.number}. {dim.name}:".ljust(42) + f"[{color}]{dim.score:.0f}/100[/{color}]"
            )
        else:
            console.print(f"  {dim.number}. {dim.name}:".ljust(42) + "[dim]not implemented[/dim]")

        for sub in dim.sub_scores:
            if sub.score is not None:
                sub_color = _score_color(sub.score)
                line = (
                    f"     {sub.name}:".ljust(42)
                    + f"[{sub_color}]{sub.score:.0f}/100[/{sub_color}]"
                )

                # Check for acceptance criterion
                for ac in report.acceptance_criteria:
                    if (
                        ac.dimension == dim.number
                        and ac.sub_score_key == sub.key
                        and ac.passed is not None
                    ):
                        tag = "[green]PASS[/green]" if ac.passed else "[red]FAIL[/red]"
                        line += f"  [Accept: >={ac.threshold:.0f} {tag}]"
                        break

                console.print(line)

                if verbose and sub.details:
                    console.print(f"       [dim]{sub.details}[/dim]")

                # Show failure summary when there are failures (always, not just verbose)
                if sub.failure_summary:
                    for fmt, counts in sorted(sub.failure_summary.items()):
                        parts = [
                            f"{n} {cat.replace('_', ' ')}{'s' if n > 1 else ''}"
                            for cat, n in sorted(counts.items())
                        ]
                        console.print(f"       [yellow]{fmt}[/yellow]: {', '.join(parts)}")
            else:
                console.print(f"     {sub.name}:".ljust(42) + "[dim]N/A[/dim]")

    # Acceptance
    console.print()
    if report.acceptance_passed is True:
        console.print("[bold green]Acceptance: PASS[/bold green] (all hard requirements met)")
    elif report.acceptance_passed is False:
        console.print("[bold red]Acceptance: FAIL[/bold red] (hard requirements not met)")
    else:
        console.print("[bold dim]Acceptance: INDETERMINATE[/bold dim] (not all dimensions scored)")

    # Flags
    if report.flags:
        console.print()
        console.print("[bold yellow]Flags:[/bold yellow]")
        for flag in report.flags:
            console.print(f"  - {flag}")

    # Verbose: sample failures
    if verbose:
        for dim in report.dimensions:
            for sub in dim.sub_scores:
                if sub.sample_failures:
                    console.print(f"\n[bold]Sample failures ({sub.name}):[/bold]")
                    for f in sub.sample_failures[:20]:
                        # Escape Rich markup brackets in failure text
                        escaped = f.replace("[", "\\[")
                        console.print(f"  {escaped}", style="dim")
                    remaining = len(sub.sample_failures) - 20
                    if remaining > 0:
                        console.print(f"  ... and {remaining} more", style="dim")

    console.print()


def format_json_report(report: QualityReport) -> str:
    """Serialize the quality report to JSON."""
    return report.model_dump_json(indent=2)


def _score_color(score: float) -> str:
    """Get a Rich color name for a score value."""
    if score >= 90:
        return "green"
    if score >= 70:
        return "yellow"
    if score >= 50:
        return "dark_orange"
    return "red"
