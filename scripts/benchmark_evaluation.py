"""Measure one fresh-process evaluation of retained data; never run generation.

Use an explicit PYTHONPATH to a clean source export with --legacy-engine for pre-change results.
The OS page cache may be warm; this script promises no persistent evaluation-cache reuse.
"""

from __future__ import annotations

import argparse
import inspect
import json
import re
import sys
from pathlib import Path
from time import perf_counter
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.composition import compile_scenario
from evidenceforge.evaluation.engine import EvaluationEngine


class Measurement(BaseModel):
    """Portable benchmark provenance, counters and measured resource use."""

    model_config = ConfigDict(extra="forbid")
    engine_source: str
    legacy_engine: bool
    bundle: str
    records: int
    memory_budget_mib: int
    verification_seconds: float
    evaluation_seconds: float
    peak_rss_bytes: int | None
    resources: dict[str, Any] | None
    report_matches_reference: bool | None = None
    phases: list[dict[str, Any]] = Field(default_factory=list)


def _peak_rss() -> int | None:
    try:
        import resource
    except ImportError:
        return None
    measured = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return measured if sys.platform == "darwin" else measured * 1024


def _comparable(report: dict[str, Any]) -> dict[str, Any]:
    report.pop("evaluated_at", None)
    report.get("supplementary", {}).pop("evaluation_resources", None)
    return report


def main() -> None:
    """Write a report and measurements outside the immutable input bundle."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--label", default="evaluation")
    parser.add_argument("--memory-budget-mib", type=int, default=256)
    parser.add_argument("--scratch-dir", type=Path)
    parser.add_argument("--legacy-engine", action="store_true")
    parser.add_argument(
        "--allow-large-evaluation",
        action="store_true",
        help="Explicit compatibility override for the legacy evaluator's corpus limits",
    )
    parser.add_argument("--compare-report", type=Path)
    args = parser.parse_args()
    bundle = args.bundle.expanduser().resolve()
    output = args.output_dir.expanduser().resolve()
    if args.memory_budget_mib < 1 or not re.fullmatch(r"[A-Za-z0-9_.-]+", args.label):
        parser.error("Choose a positive memory budget and a simple filename label")
    if output.is_relative_to(bundle):
        parser.error("Benchmark outputs must be outside the input bundle")
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / f"{args.label}-report.json"
    metrics_path = output / f"{args.label}-metrics.json"
    if report_path.exists() or metrics_path.exists():
        parser.error("Choose a new label; existing benchmark artifacts are retained")
    started = perf_counter()
    kwargs: dict[str, Any] = {"allow_large_evaluation": args.allow_large_evaluation}
    if args.legacy_engine:
        from evidenceforge.composition.artifacts import verify_generation_bundle

        verify_generation_bundle(bundle)
    else:
        from evidenceforge.evaluation.bundle import verify_evaluation_bundle

        kwargs.update(
            memory_budget_bytes=args.memory_budget_mib * 1024 * 1024, scratch_dir=args.scratch_dir
        )
        verify_evaluation_bundle(
            bundle, memory_budget_bytes=kwargs["memory_budget_bytes"], scratch_dir=args.scratch_dir
        )
    verified = perf_counter()
    compiled = compile_scenario(bundle / "RESOLVED_SCENARIO.yaml")
    phases: list[dict[str, Any]] = []

    def progress(event: str, payload: dict[str, Any]) -> None:
        if event in {
            "phase_start",
            "phase_done",
            "dimension_start",
            "dimension_done",
            "sub_score_done",
        }:
            phases.append(
                {"event": event, "since_start_seconds": perf_counter() - started, **payload}
            )

    report = EvaluationEngine(
        bundle / "data",
        compiled.scenario,
        effective_config=compiled.effective_config,
        progress_callback=progress,
        **kwargs,
    ).run()
    finished = perf_counter()
    report_path.write_text(report.model_dump_json(indent=2) + "\n")
    matches = None
    if args.compare_report is not None:
        reference = json.loads(args.compare_report.read_text())
        matches = _comparable(report.model_dump(mode="json")) == _comparable(reference)
    measurement = Measurement(
        engine_source=str(Path(inspect.getfile(EvaluationEngine)).resolve()),
        legacy_engine=args.legacy_engine,
        bundle=str(bundle),
        records=report.total_records,
        memory_budget_mib=args.memory_budget_mib,
        verification_seconds=verified - started,
        evaluation_seconds=finished - verified,
        peak_rss_bytes=_peak_rss(),
        resources=report.supplementary.get("evaluation_resources"),
        report_matches_reference=matches,
        phases=phases,
    )
    metrics_path.write_text(measurement.model_dump_json(indent=2) + "\n")
    print(measurement.model_dump_json(exclude={"phases"}))
    if matches is False:
        raise SystemExit("Report differs from the reference; inspect the saved reports")


if __name__ == "__main__":
    main()
