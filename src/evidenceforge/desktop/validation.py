"""Readable desktop summary of the CLI's stable validation JSON."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class ValidationIssue(BaseModel):
    """One actionable validation finding."""

    model_config = ConfigDict(extra="forbid")

    severity: str
    field_path: str
    message: str
    suggestion: str | None = None


class ValidationReport(BaseModel):
    """Subset of CLI validation output relevant to the desktop summary."""

    model_config = ConfigDict(extra="forbid")

    valid: bool
    status: str
    scenario_name: str | None = None
    users: int | None = None
    systems: int | None = None
    storyline_events: int | None = None
    formats: list[str] = Field(default_factory=list)
    memory_bytes: int | None = None
    output_bytes: int | None = None
    issues: list[ValidationIssue] = Field(default_factory=list)


def _byte_size(value: int) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    amount = float(value)
    for unit in units[:-1]:
        if amount < 1024:
            return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} {units[-1]}"


def _report_from_payload(payload: dict[str, Any]) -> ValidationReport:
    scenario = payload.get("scenario") or {}
    forecast = payload.get("resource_forecast") or {}
    issues = [
        {
            "severity": issue.get("severity"),
            "field_path": issue.get("field_path"),
            "message": issue.get("message"),
            "suggestion": issue.get("suggestion"),
        }
        for issue in payload.get("issues", [])
    ]
    return ValidationReport.model_validate(
        {
            "valid": payload.get("valid"),
            "status": payload.get("status"),
            "scenario_name": scenario.get("name"),
            "users": scenario.get("users"),
            "systems": scenario.get("systems"),
            "storyline_events": scenario.get("storyline_events"),
            "formats": scenario.get("output_formats", []),
            "memory_bytes": (forecast.get("memory") or {}).get("expected_bytes"),
            "output_bytes": (forecast.get("final_output") or {}).get("expected_bytes"),
            "issues": issues,
        }
    )


def format_validation_output(stdout: str, stderr: str, exit_code: int) -> str:
    """Turn verbose machine output into a compact, actionable report."""
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return stderr.strip() or stdout.strip() or f"Validation exited with code {exit_code}."
    if not isinstance(payload, dict):
        return stderr.strip() or f"Validation returned an unexpected response (exit {exit_code})."
    if payload.get("error"):
        return f"Validation failed\n\n{payload['error']}"
    try:
        report = _report_from_payload(payload)
    except (ValidationError, AttributeError, TypeError):
        return stderr.strip() or f"Validation returned an unexpected response (exit {exit_code})."

    counts = {
        severity: sum(issue.severity == severity for issue in report.issues)
        for severity in ("error", "warning", "info")
    }
    name = f" · {report.scenario_name}" if report.scenario_name else ""
    if not report.valid:
        headline = f"VALIDATION FAILED{name}"
    elif counts["warning"]:
        headline = f"VALID WITH WARNINGS{name}"
    else:
        headline = f"VALID{name}"
    lines = [headline]
    if report.users is not None and report.systems is not None:
        user_label = "user" if report.users == 1 else "users"
        system_label = "system" if report.systems == 1 else "systems"
        storyline_label = "storyline event" if report.storyline_events == 1 else "storyline events"
        lines.append(
            f"{report.users} {user_label} · {report.systems} {system_label} · "
            f"{report.storyline_events or 0} {storyline_label}"
        )
    if report.formats:
        lines.append(f"Formats: {', '.join(report.formats)}")
    resources = []
    if report.memory_bytes is not None:
        resources.append(f"peak memory ~{_byte_size(report.memory_bytes)}")
    if report.output_bytes is not None:
        resources.append(f"output ~{_byte_size(report.output_bytes)}")
    if resources:
        lines.append(f"Estimated {' · '.join(resources)}")
    if not report.issues:
        lines.extend(("", "No validation issues found."))
    else:
        lines.extend(("", f"{len(report.issues)} finding(s):"))
        for issue in report.issues:
            lines.append(f"{issue.severity.upper()} · {issue.field_path}")
            lines.append(f"  {issue.message}")
            if issue.suggestion:
                lines.append(f"  Suggested fix: {issue.suggestion}")
    return "\n".join(lines)
