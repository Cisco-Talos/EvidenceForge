"""Report integrity, verification, and experimental baseline comparison."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import AcceptanceReport, ExperimentalBaseline
from .util import atomic_write_json, canonical_json_bytes, sha256_bytes

BASELINE_PATH = Path(__file__).resolve().parent / "baseline.json"


def report_digest(payload: dict[str, Any]) -> str:
    """Hash a report while excluding its self-referential digest field."""

    unsigned = dict(payload)
    unsigned.pop("report_digest", None)
    return sha256_bytes(canonical_json_bytes(unsigned))


def write_report(path: Path, report: AcceptanceReport) -> None:
    """Set and atomically write the report digest."""

    payload = report.model_dump(mode="json")
    payload["report_digest"] = report_digest(payload)
    atomic_write_json(path, payload)


def load_verified_report(path: Path) -> AcceptanceReport:
    """Load a report and reject content tampering or schema drift."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    report = AcceptanceReport.model_validate(payload)
    expected = report_digest(payload)
    if report.report_digest != expected:
        raise ValueError(
            f"report digest mismatch: expected {expected}, found {report.report_digest}"
        )
    return report


def compare_baseline(report: AcceptanceReport, baseline: ExperimentalBaseline) -> list[str]:
    """Return ratchet regressions; strict invariants are enforced independently."""

    regressions: list[str] = []
    if report.suite != baseline.suite:
        return [f"suite mismatch: report={report.suite} baseline={baseline.suite}"]
    if (
        report.aggregate.first_complete_draft_successes
        < baseline.aggregate.first_complete_draft_successes
    ):
        regressions.append("first-complete-draft successes decreased")
    if (
        report.aggregate.total_validation_passes_to_zero
        > baseline.aggregate.total_validation_passes_to_zero
    ):
        regressions.append("total validation passes to zero increased")
    report_median = report.aggregate.median_validation_passes_to_zero
    baseline_median = baseline.aggregate.median_validation_passes_to_zero
    if (
        report_median is not None
        and baseline_median is not None
        and report_median > baseline_median
    ):
        regressions.append("median validation passes to zero increased")
    report_maximum = report.aggregate.maximum_validation_passes_to_zero
    baseline_maximum = baseline.aggregate.maximum_validation_passes_to_zero
    if (
        report_maximum is not None
        and baseline_maximum is not None
        and report_maximum > baseline_maximum
    ):
        regressions.append("maximum validation passes to zero increased")
    if report.aggregate.total_introduced_warnings > baseline.aggregate.total_introduced_warnings:
        regressions.append("introduced warning count increased")
    if report.aggregate.total_unexpected_warnings > baseline.aggregate.total_unexpected_warnings:
        regressions.append("unexpected warning count increased")
    if report.aggregate.repair_regressions > baseline.aggregate.repair_regressions:
        regressions.append("repair regression count increased")
    return regressions


def baseline_from_report(report: AcceptanceReport) -> ExperimentalBaseline:
    """Create an aggregate-only baseline candidate."""

    return ExperimentalBaseline(
        created_at=datetime.now().astimezone(),
        source_report_digest=report.report_digest,
        suite=report.suite,
        inputs=report.inputs,
        aggregate=report.aggregate,
    )


def write_baseline(path: Path, baseline: ExperimentalBaseline) -> None:
    """Atomically write the compact baseline."""

    atomic_write_json(path, baseline.model_dump(mode="json"))


def load_baseline(path: Path = BASELINE_PATH) -> ExperimentalBaseline | None:
    """Load the baseline when the experiment has an accepted candidate."""

    if not path.exists():
        return None
    return ExperimentalBaseline.model_validate_json(path.read_text(encoding="utf-8"))
