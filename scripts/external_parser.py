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

"""Run external parser harnesses against generated EvidenceForge data."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from evidenceforge.external_parsers.runner import (
    VALIDATOR_ORDER,
    ExternalParserPlan,
    detect_external_parser_plan,
    unsupported_summary,
)
from evidenceforge.external_parsers.sof_elk import (
    COMBINED_VALIDATOR_NAME,
    SofElkCombinedResult,
    run_sof_elk_parser,
)
from evidenceforge.external_parsers.sof_elk_sources import SOF_ELK_SOURCE_SPECS_BY_VALIDATOR
from evidenceforge.external_parsers.sof_elk_zeek import (
    FAILURE_REPORT_FILENAME,
    SOF_ELK_ZEEK_VALIDATOR,
    SofElkHarnessError,
    SofElkParserError,
)

INGEST_STEP_TOTAL = 5
console = Console()
error_console = Console(stderr=True)


def main(argv: list[str] | None = None) -> int:
    """Run the external parser CLI."""
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    return _run(args)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    legacy_validator: str | None = None
    if argv and argv[0] in VALIDATOR_ORDER:
        legacy_validator = argv.pop(0)

    parser = argparse.ArgumentParser(
        description=(
            "Run external parser validation against generated EvidenceForge data. "
            "By default, the runner auto-detects generated log families and runs "
            "every matching external validator."
        ),
    )
    parser.add_argument("data_dir", type=Path, help="Generated EvidenceForge data/ directory")
    parser.add_argument(
        "--work-dir",
        type=Path,
        help="Directory for staged files, parsed JSONL, logs, and reports",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Seconds to wait for parser output before failing",
    )
    parser.add_argument(
        "--runtime",
        choices=("docker", "podman"),
        help="Compose-backed container runtime to use; default auto-detects Docker then Podman",
    )
    parser.add_argument(
        "--validator",
        action="append",
        choices=VALIDATOR_ORDER,
        help="Limit execution to a specific validator; may be repeated",
    )

    args = parser.parse_args(argv)
    if legacy_validator:
        args.validator = [legacy_validator, *(args.validator or [])]
    return args


def _run(args: argparse.Namespace) -> int:
    data_dir = args.data_dir.resolve()
    if not data_dir.is_dir():
        console.print(f"[bold red]error:[/bold red] data directory does not exist: {data_dir}")
        return 1

    work_dir = (
        args.work_dir.resolve()
        if args.work_dir
        else Path(tempfile.mkdtemp(prefix="eforge-external-parsers-"))
    )
    plan = detect_external_parser_plan(data_dir)
    validators = _selected_validators(plan, args.validator)

    console.print(f"[bold]Data directory:[/bold] {data_dir}")
    console.print(f"[bold]Work directory:[/bold] {work_dir}")
    _print_plan_summary(plan, validators)

    if not plan.logs:
        console.print("[bold red]ERROR:[/bold red] no generated log files were found")
        return 1
    if not validators:
        console.print("[yellow]Warning:[/yellow] no external validators matched this dataset")
        return 0

    return _run_validators(
        validators,
        data_dir=data_dir,
        work_dir=work_dir / "sof-elk",
        timeout=args.timeout,
        runtime=args.runtime,
    )


def _selected_validators(
    plan: ExternalParserPlan,
    requested_validators: list[str] | None,
) -> tuple[str, ...]:
    if not requested_validators:
        return plan.validators
    requested = tuple(dict.fromkeys(requested_validators))
    return tuple(validator for validator in VALIDATOR_ORDER if validator in requested)


def _print_plan_summary(plan: ExternalParserPlan, validators: tuple[str, ...]) -> None:
    console.print(f"\n[bold]Discovered logs:[/bold] {len(plan.logs)} file(s)")
    if validators:
        console.print(f"[bold]Validators:[/bold] {', '.join(validators)}")
        _print_validated_log_summary(plan, validators)

    unsupported = unsupported_summary(plan.unsupported_logs)
    for logtype, subtypes in unsupported.items():
        console.print(
            f"[yellow]Warning:[/yellow] no external validator for {logtype}: {', '.join(subtypes)}"
        )


def _print_validated_log_summary(
    plan: ExternalParserPlan,
    validators: tuple[str, ...],
) -> None:
    selected = set(validators)
    counts: Counter[tuple[str, str, str]] = Counter()
    for log in plan.supported_logs:
        if log.validator not in selected or log.format_name is None:
            continue
        output_label = _validator_output_label(log.validator, log.format_name)
        counts[(log.format_name, _validator_display_name(log.validator), output_label)] += 1

    if not counts:
        return

    console.print("\n[bold]Validated log families:[/bold]")
    for (format_name, display_name, output_label), count in sorted(counts.items()):
        console.print(f"  {format_name}: {count} file(s) -> {display_name} ({output_label}.jsonl)")


def _validator_display_name(validator: str) -> str:
    if validator == SOF_ELK_ZEEK_VALIDATOR:
        return "SOF-ELK Zeek"
    spec = SOF_ELK_SOURCE_SPECS_BY_VALIDATOR.get(validator)
    return spec.display_name if spec else validator


def _validator_output_label(validator: str | None, format_name: str) -> str:
    if validator is None or validator == SOF_ELK_ZEEK_VALIDATOR:
        return format_name
    spec = SOF_ELK_SOURCE_SPECS_BY_VALIDATOR.get(validator)
    return spec.output_label_type if spec else format_name


def _run_validators(
    validators: tuple[str, ...],
    *,
    data_dir: Path,
    work_dir: Path,
    timeout: int,
    runtime: str | None,
) -> int:
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        ingest_task = progress.add_task(
            "Ingesting logs with SOF-ELK",
            total=INGEST_STEP_TOTAL,
        )
        validation_task = progress.add_task(
            "Validating parsed JSONL: pending",
            total=1,
            visible=False,
        )
        host_task = progress.add_task(
            "Validating parsed JSONL: host pending",
            total=1,
            visible=False,
        )
        logtype_task = progress.add_task(
            "Validating parsed JSONL: logtype pending",
            total=1,
            visible=False,
        )
        subtype_task = progress.add_task(
            "Validating parsed JSONL: subtype pending",
            total=1,
            visible=False,
        )

        def progress_callback(event_type: str, data: dict[str, Any]) -> None:
            if event_type == "validator_step":
                description = str(data["description"])
                if description in {"Validating parsed JSONL", "Checking parsed output"}:
                    progress.update(
                        ingest_task,
                        completed=INGEST_STEP_TOTAL,
                        description="Ingesting logs with SOF-ELK: complete",
                    )
                    progress.update(
                        validation_task,
                        completed=0,
                        description="Validating parsed JSONL",
                        visible=True,
                    )
                else:
                    progress.update(
                        ingest_task,
                        advance=1,
                        description=f"Ingesting logs with SOF-ELK: {description}",
                    )
            elif event_type == "validator_scope_progress":
                host = str(data["host"])
                logtype = str(data["logtype"])
                subtype = str(data["subtype"])
                progress.update(
                    host_task,
                    completed=int(data["host_completed"]),
                    total=max(1, int(data["host_total"])),
                    description=f"Validating parsed JSONL: host {host}",
                    visible=True,
                )
                progress.update(
                    logtype_task,
                    completed=int(data["logtype_completed"]),
                    total=max(1, int(data["logtype_total"])),
                    description=f"Validating parsed JSONL: logtype {logtype}",
                    visible=True,
                )
                progress.update(
                    subtype_task,
                    completed=int(data["subtype_completed"]),
                    total=max(1, int(data["subtype_total"])),
                    description=f"Validating parsed JSONL: subtype {subtype}",
                    visible=True,
                )
            elif event_type == "validator_done":
                description = str(data["description"])
                failed = "failed" in description.lower()
                progress.update(
                    ingest_task,
                    completed=INGEST_STEP_TOTAL,
                    description="Ingesting logs with SOF-ELK: complete",
                )
                progress.update(
                    validation_task,
                    completed=1,
                    description=(
                        "Validating parsed JSONL: failed"
                        if failed
                        else "Validating parsed JSONL: complete"
                    ),
                    visible=True,
                )

        try:
            result = run_sof_elk_parser(
                data_dir,
                work_dir,
                validators=validators,
                timeout_seconds=timeout,
                runtime=runtime,
                progress_callback=progress_callback,
            )
        except SofElkParserError as exc:
            progress.stop()
            error_console.print(f"\n[bold red]FAIL:[/bold red] {exc}")
            _print_failure_report(work_dir / "parsed" / FAILURE_REPORT_FILENAME)
            _print_artifact_paths(work_dir)
            return 2
        except SofElkHarnessError as exc:
            progress.stop()
            error_console.print(f"\n[bold red]ERROR:[/bold red] {exc}")
            _print_artifact_paths(work_dir)
            return 1

    _print_success(result)
    _print_artifact_paths(work_dir)
    return 0


def _print_success(result: SofElkCombinedResult) -> None:
    console.print(
        f"\n[bold green]PASS:[/bold green] {COMBINED_VALIDATOR_NAME} parsed staged records"
    )
    console.print(f"Expected counts: {result.manifest.expected_counts}")
    console.print(f"SOF-ELK output labels: {result.manifest.expected_output_counts}")
    console.print(
        "Observed counts: "
        f"{ {log_type: len(events) for log_type, events in result.events_by_type.items() if events} }"
    )


def _print_failure_report(report_path: Path) -> None:
    if not report_path.exists():
        console.print(f"Failure report: missing ({report_path})")
        return

    with report_path.open("r", encoding="utf-8") as handle:
        report = json.load(handle)

    console.print("\n[bold]Failure summary:[/bold]")
    console.print(f"  Report: {report_path}")
    console.print(f"  Expected counts: {report.get('expected_counts', {})}")
    console.print(f"  Observed counts: {report.get('observed_counts', {})}")
    console.print(f"  Failure count: {report.get('failure_count', 0)}")
    console.print(f"  Failure tag counts: {report.get('failure_tag_counts', {})}")
    dns_qtypes = report.get("dns_failure_qtype_counts")
    if dns_qtypes:
        console.print(f"  DNS failures by qtype: {dns_qtypes}")


def _print_artifact_paths(work_dir: Path) -> None:
    console.print("\n[bold]Artifacts:[/bold]")
    console.print(f"  Staged input: {work_dir / 'stage' / 'logstash'}")
    console.print(f"  Parsed JSONL: {work_dir / 'parsed'}")
    console.print(f"  Pipeline logs: {work_dir / 'pipeline-logs'}")
    console.print(f"  Compose file: {work_dir / 'compose.yaml'}")
    console.print(f"  EvidenceForge runtime config: {work_dir / 'runtime-config-src'}")


if __name__ == "__main__":
    raise SystemExit(main())
