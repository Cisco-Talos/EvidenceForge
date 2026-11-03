# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Measure the fixed synthetic workstation through the public CLI, without native collection."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict

from evidenceforge.events.ground_truth import GroundTruthDocument
from evidenceforge.events.macos_native_coverage import MacosNativeCoverage
from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record


class RequiredExecution(BaseModel):
    """Keep distinct operational roles when two helpers share one executable."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    image: str
    arguments: tuple[str, ...]


class Case(BaseModel):
    """An independently authored activity and its required executable roles."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str
    description: str
    steps: tuple[str, ...]
    required_images: tuple[str, ...]
    required_executions: tuple[RequiredExecution, ...] = ()
    allowed_noop_steps: tuple[str, ...] = ()


class Workload(BaseModel):
    """Fixed source and diagnostic slice membership, never generator configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal[1]
    source: str
    purpose: str
    duration: str
    seed: int
    acceptance: dict[str, bool | str]
    common_steps: tuple[str, ...]
    cases: tuple[Case, ...]
    allowed_noop_steps: tuple[str, ...] = ()


class Measurement(BaseModel):
    """A failed run has unknown counts, never fabricated zero coverage."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str
    scope: Literal["full", "diagnostic_slice"]
    exit_code: int
    blocker: str | None = None
    coverage: MacosNativeCoverage | None = None
    native_exec_images: dict[str, int] | None = None
    missing_images: tuple[str, ...] = ()
    missing_execution_roles: tuple[int, ...] = ()
    unrealized_steps: tuple[str, ...] = ()
    authored_phase_gaps: tuple[str, ...] = ()
    background_native_execs: int | None = None
    activity_supported: bool = False
    census_complete: bool = False
    manifest_sha256: str | None = None
    actual_seed: int | None = None
    target: str | None = None


def slice_document(document: dict[str, Any], case: Case, common: tuple[str, ...]) -> dict[str, Any]:
    """Select documented activities without changing apps, times, seed or baseline."""
    selected = set(case.steps) | set(common)
    return document | {
        "macos_process_coverage": "partial",
        "storyline": [step for step in document["storyline"] if step["id"] in selected],
    }


def _visible_execs(observations: Any) -> int:
    return sum(
        item.count
        for item in observations
        if item.phase == "exec"
        and item.reason == "supported"
        and item.status in {"visible", "delayed"}
    )


def missing_execution_roles(
    requirements: tuple[RequiredExecution, ...],
    native_arguments: list[tuple[str, tuple[str, ...]]],
) -> tuple[int, ...]:
    """Require the operational invocation as well as its physical executable."""
    return tuple(
        index
        for index, requirement in enumerate(requirements)
        if not any(
            image == requirement.image
            and arguments[1 : 1 + len(requirement.arguments)] == requirement.arguments
            for image, arguments in native_arguments
        )
    )


def realized_step_ids(
    events: tuple[Any, ...] | list[Any], allowed_noop_steps: tuple[str, ...]
) -> set[str]:
    """Count only explicit optional cleanup no-ops alongside evidence-producing steps."""
    return {
        event.storyline_id
        for event in events
        if event.emitted
        or event.storyline_id in allowed_noop_steps
        and event.kind == "logoff"
        and event.skipped_reason == "no_matching_session"
    }


def summarize(output: Path, case: Case, *, full: bool, exit_code: int, text: str) -> Measurement:
    """Require actual activity, native roles and the independent census separately."""
    base = {
        "name": case.name,
        "scope": "full" if full else "diagnostic_slice",
        "exit_code": exit_code,
    }
    if exit_code != 0:
        normalized = " ".join(text.split())
        match = re.search(
            r"(?:Error: Generation failed:|Fatal error:|Error:)(.*?)(?: \[\d\d/|$)", normalized
        )
        return Measurement(
            **base, blocker=(match[1].strip()[:1200] if match else normalized[-1200:])
        )
    if not (output / "GENERATION_MANIFEST.json").is_file():
        return Measurement(**base, blocker="CLI returned success without its completion manifest")
    truth = GroundTruthDocument.model_validate_json((output / "GROUND_TRUTH.json").read_bytes())
    manifest_bytes = (output / "GENERATION_MANIFEST.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    coverage = truth.macos_native_coverage
    images: dict[str, int] = {}
    native_executions: set[tuple[str, int, str]] = set()
    native_arguments: list[tuple[str, tuple[str, ...]]] = []
    for path in sorted((output / "data").rglob("macos_endpoint_security.ndjson")):
        with path.open() as stream:
            for line in stream:
                record = decode_endpoint_security_record(line)
                if record.event_type == 9:
                    image = record.event.exec.target.executable.path
                    images[image] = images.get(image, 0) + 1
                    native_arguments.append((image, tuple(record.event.exec.args)))
                    owner = (
                        next(
                            (
                                host.hostname
                                for host in coverage.hosts
                                if path.parent.name == host.hostname
                                or path.parent.name.startswith(host.hostname + ".")
                            ),
                            None,
                        )
                        if coverage is not None
                        else None
                    )
                    if owner is not None:
                        native_executions.add(
                            (owner, record.event.exec.target.audit_token.pid, image)
                        )
    intended = set(case.steps)
    realized = realized_step_ids(truth.events, case.allowed_noop_steps)
    missing_steps = tuple(sorted(intended - realized))
    # Setup/registration and dormant unload intentionally have no source row.
    missing_steps = tuple(
        step
        for step in missing_steps
        if not step.startswith("setup-") and step != "inventory-unload"
    )
    missing = tuple(image for image in case.required_images if not images.get(image))
    missing_roles = missing_execution_roles(case.required_executions, native_arguments)
    gaps: list[str] = []
    eligible_steps = {
        event.storyline_id
        for event in truth.events
        for host in (coverage.hosts if coverage is not None else ())
        if host.hostname == event.system
        and host.process_census is not None
        and host.process_census.window_start <= event.time < host.process_census.window_end
    }
    for event in truth.events:
        if (
            event.storyline_id in intended & eligible_steps
            and event.kind == "process"
            and event.emitted
        ):
            if (
                event.system,
                event.attributes.pid,
                event.attributes.process_name,
            ) not in native_executions:
                gaps.append(f"{event.storyline_id}:exec:authored_identity_missing")
    background: int | None = None
    complete = False
    if coverage is not None and coverage.hosts:
        complete = all(
            host.process_census is not None and host.process_census.complete
            for host in coverage.hosts
        )
        background = sum(
            _visible_execs(host.observations)
            - sum(_visible_execs(action.observations) for action in host.authored_actions)
            for host in coverage.hosts
        )
        for host in coverage.hosts:
            for action in host.authored_actions:
                if action.storyline_cluster_id in intended & eligible_steps:
                    gaps.extend(
                        f"{action.storyline_cluster_id}:{item.phase}:{item.reason}"
                        for item in action.observations
                        if item.phase in {"aggregate_birth", "fork", "exec"}
                        and item.reason != "supported"
                        and item.status != "out_of_window"
                    )
    supported = (
        not missing
        and not missing_roles
        and not missing_steps
        and not gaps
        and coverage is not None
    )
    if case.name == "baseline":
        supported = supported and bool(background) and complete
    return Measurement(
        **base,
        coverage=coverage,
        native_exec_images=images,
        missing_images=missing,
        missing_execution_roles=missing_roles,
        unrealized_steps=missing_steps,
        authored_phase_gaps=tuple(sorted(set(gaps))),
        background_native_execs=background,
        census_complete=complete,
        activity_supported=supported,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        actual_seed=manifest["generation_seed"],
        target=manifest["output_target"],
    )


def main() -> None:
    """Create fresh synthetic measurements; no native commands or private captures are used."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workload", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    workload_path, root = arguments.workload.resolve(), arguments.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    spec = Workload.model_validate(yaml.safe_load(workload_path.read_text()))
    source = (workload_path.parent / spec.source).resolve()
    document = yaml.safe_load(source.read_text())
    steps = tuple(step["id"] for step in document["storyline"])
    declared_steps = set(spec.common_steps) | {step for case in spec.cases for step in case.steps}
    if (
        declared_steps != set(steps)
        or len(set(steps)) != len(steps)
        or document["time_window"]["duration"] != spec.duration
        or document.get("generation_seed") != spec.seed
        or document.get("macos_process_coverage") != "complete"
    ):
        parser.error(
            "Source scope, duration, seed or completeness policy differs from WORKLOAD.yaml"
        )
    all_images = tuple(
        dict.fromkeys(image for case in spec.cases for image in case.required_images)
    )
    full = Case(
        name="full",
        description="Unchanged acceptance source",
        steps=steps,
        required_images=all_images,
        required_executions=tuple(
            requirement for case in spec.cases for requirement in case.required_executions
        ),
        allowed_noop_steps=spec.allowed_noop_steps,
    )
    chrome = next(case for case in spec.cases if case.name == "chrome")
    combined = Case(
        name="supported-combined",
        description="Diagnostic only: all activities except blocked Chrome",
        steps=tuple(step for step in steps if step not in chrome.steps),
        required_images=tuple(image for image in all_images if image not in chrome.required_images),
    )
    measurements: list[Measurement] = []
    for case in (full, *spec.cases, combined):
        authored = source
        if case.name != "full":
            authored = root / f"{case.name}.yaml"
            authored.write_text(
                yaml.safe_dump(slice_document(document, case, spec.common_steps), sort_keys=False)
            )
        output = root / case.name
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "evidenceforge",
                "generate",
                str(authored),
                "--output",
                str(output),
                "--seed",
                str(spec.seed),
                "--checkpoint-hours",
                "0",
            ],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        (root / f"{case.name}-stdout.txt").write_text(result.stdout)
        (root / f"{case.name}-stderr.txt").write_text(result.stderr)
        measurement = summarize(
            output,
            case,
            full=case.name == "full",
            exit_code=result.returncode,
            text=result.stdout + result.stderr,
        )
        measurements.append(measurement)
        print(
            f"{case.name}: exit={measurement.exit_code} activity={measurement.activity_supported} census={measurement.census_complete}",
            flush=True,
        )
    passed = (
        measurements[0].activity_supported
        and measurements[0].census_complete
        and bool(measurements[0].background_native_execs)
    )
    (root / "RESULTS.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "seed": spec.seed,
                "full_process_coverage_passed": passed,
                "filter_recovery_and_ecar_checks": "NOT_RUN_FOR_FULL_WORKLOAD",
                "measurements": [
                    measurement.model_dump(mode="json") for measurement in measurements
                ],
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
