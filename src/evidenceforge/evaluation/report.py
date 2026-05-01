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

"""Report formatting for evaluation results.

Supports Rich text (terminal) and JSON output formats.
"""

from rich.console import Console

from evidenceforge.evaluation.models import AcceptanceCriterion, QualityReport, SubScore


def format_text_report(report: QualityReport, console: Console, verbose: bool = False) -> None:
    """Print a pillar-oriented quality report to the Rich console."""
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
        console.print("[bold]Overall Quality Score:[/bold] [dim]N/A (insufficient pillars)[/dim]")

    # Aspirational summary line
    if report.aspirational_total:
        asp_pct = 100.0 * (report.aspirational_met or 0) / report.aspirational_total
        asp_color = "green" if asp_pct >= 80 else "yellow" if asp_pct >= 50 else "dark_orange"
        console.print(
            f"[bold]Aspirational targets:[/bold] "
            f"[{asp_color}]{report.aspirational_met}/{report.aspirational_total} "
            f"({asp_pct:.0f}%)[/{asp_color}]"
        )

    console.print()

    # Build sub-score key → acceptance criterion map for fast lookup
    ac_by_key: dict[str, AcceptanceCriterion] = {
        ac.sub_score_key: ac for ac in report.acceptance_criteria
    }

    # Pillar scores table
    console.print("[bold]Pillar Scores:[/bold]")
    for pillar in report.pillars:
        if pillar.score is not None:
            color = _score_color(pillar.score)
            console.print(
                f"  {pillar.number}. {pillar.name}:".ljust(42)
                + f"[{color}]{pillar.score:.0f}/100[/{color}]"
            )
        else:
            console.print(
                f"  {pillar.number}. {pillar.name}:".ljust(42) + "[dim]not implemented[/dim]"
            )

        for sub in pillar.sub_scores:
            _print_sub_score(console, sub, ac_by_key, verbose)

    # Acceptance verdict
    console.print()
    if report.acceptance_passed is True:
        console.print("[bold green]Acceptance: PASS[/bold green] (all hard requirements met)")
    elif report.acceptance_passed is False:
        console.print("[bold red]Acceptance: FAIL[/bold red] (hard requirements not met)")
    else:
        console.print("[bold dim]Acceptance: INDETERMINATE[/bold dim] (not all pillars scored)")

    # Acceptance criteria detail (always show hard-failed ones; verbose shows all)
    hard_failed = [c for c in report.acceptance_criteria if c.passed is False]
    if hard_failed:
        console.print()
        console.print("[bold yellow]Failed hard requirements:[/bold yellow]")
        for c in hard_failed:
            asp_note = ""
            if c.aspirational is not None:
                asp_note = f" (aspirational: {c.aspirational:.0f})"
            console.print(
                f"  [red]FAIL[/red] {c.name}: {c.actual:.1f} < {c.threshold:.0f} minimum{asp_note}"
            )

    if verbose and report.acceptance_criteria:
        console.print()
        console.print("[bold]All acceptance criteria:[/bold]")
        for c in report.acceptance_criteria:
            if c.passed is True:
                tag = "[green]PASS[/green]"
            elif c.passed is False:
                tag = "[red]FAIL[/red]"
            else:
                tag = "[dim]N/A[/dim]"

            actual_str = f"{c.actual:.1f}" if c.actual is not None else "N/A"
            asp_str = f"  aspirational: {c.aspirational:.0f}" if c.aspirational else ""
            console.print(f"  {tag} {c.name}: {actual_str} vs min {c.threshold:.0f}{asp_str}")

    # Flags
    if report.flags:
        console.print()
        console.print("[bold yellow]Flags:[/bold yellow]")
        for flag in report.flags:
            console.print(f"  - {flag}")

    # Supplementary: Host Log Profile
    host_profile = report.supplementary.get("host_log_profile")
    if host_profile and (verbose or any(h.get("missing_formats") for h in host_profile.values())):
        console.print()
        console.print("[bold dim]Host Log Profile (informational):[/bold dim]")
        for host, info in sorted(host_profile.items()):
            missing = info.get("missing_formats", [])
            if missing:
                console.print(f"  [yellow]{host}[/yellow]: missing formats: {', '.join(missing)}")
            elif verbose:
                console.print(f"  {host}: all expected formats present")

    # Verbose: sample failures per sub-score
    if verbose:
        for pillar in report.pillars:
            for sub in pillar.sub_scores:
                if sub.sample_failures:
                    console.print(f"\n[bold]Sample failures ({sub.name}):[/bold]")
                    for f in sub.sample_failures[:20]:
                        escaped = f.replace("[", "\\[")
                        console.print(f"  {escaped}", style="dim")
                    remaining = len(sub.sample_failures) - 20
                    if remaining > 0:
                        console.print(f"  ... and {remaining} more", style="dim")

    console.print()


def _print_sub_score(
    console: Console,
    sub: SubScore,
    ac_by_key: dict[str, AcceptanceCriterion],
    verbose: bool,
) -> None:
    if sub.score is not None:
        sub_color = _score_color(sub.score)
        line = f"     {sub.name}:".ljust(42) + f"[{sub_color}]{sub.score:.0f}/100[/{sub_color}]"

        # Acceptance tag: show minimum gate and aspirational if present
        ac = ac_by_key.get(sub.key)
        if ac is not None and ac.passed is not None:
            gate_tag = "[green]PASS[/green]" if ac.passed else "[red]FAIL[/red]"
            line += f"  [min:{ac.threshold:.0f} {gate_tag}]"
            if ac.aspirational is not None and ac.meets_aspirational is not None:
                asp_tag = "[green]met[/green]" if ac.meets_aspirational else "[dim]below[/dim]"
                line += f" [asp:{ac.aspirational:.0f} {asp_tag}]"

        console.print(line)

        if verbose and sub.details:
            console.print(f"       [dim]{sub.details}[/dim]")

        if sub.failure_summary:
            for fmt, counts in sorted(sub.failure_summary.items()):
                parts = [
                    f"{n} {cat.replace('_', ' ')}{'s' if n > 1 else ''}"
                    for cat, n in sorted(counts.items())
                ]
                console.print(f"       [yellow]{fmt}[/yellow]: {', '.join(parts)}")
    else:
        console.print(f"     {sub.name}:".ljust(42) + "[dim]N/A[/dim]")


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
