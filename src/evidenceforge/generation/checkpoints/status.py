"""Read-only checkpoint health, compatibility, and storage diagnostics."""

from __future__ import annotations

import math
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.composition import compile_scenario
from evidenceforge.composition.artifacts import (
    GENERATION_MANIFEST_FILENAME,
    verify_generation_bundle,
)
from evidenceforge.composition.sidecars import SIDECAR_REGISTRY
from evidenceforge.config.provider import effective_config_scope
from evidenceforge.generation.resource_forecast import build_resource_forecast
from evidenceforge.generation.workload import estimate_workload
from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.time import parse_duration, resolve_time_window

from .control import read_controller_record, read_suspension_record, read_suspension_request
from .errors import CheckpointError
from .fingerprint import run_fingerprint, run_fingerprint_components
from .models import CheckpointRecovery
from .store import IncrementalCheckpointStore


class _InspectingCheckpointStore(IncrementalCheckpointStore):
    """Count content bytes authenticated by the standalone read-only inspector."""

    def __init__(self, output_root: Path) -> None:
        super().__init__(output_root)
        self.validation_bytes_hashed = 0

    def _validate_file(self, relative_path: str, expected_size: int, expected_hash: str) -> bytes:
        payload = super()._validate_file(relative_path, expected_size, expected_hash)
        self.validation_bytes_hashed += len(payload)
        return payload


class StorageUsage(BaseModel):
    """Non-overlapping managed storage totals for one output root."""

    generated_bytes: int = Field(ge=0, description="Generated staged or published bundle bytes")
    checkpoint_bytes: int = Field(ge=0, description="Checkpoint workspace bytes excluding staging")
    recovery_overhead_bytes: int = Field(
        ge=0,
        description="Checkpoint recovery overhead within the output root",
    )
    prior_bundle_bytes: int = Field(
        ge=0,
        description="Published managed bundle retained during replacement generation",
    )
    total_managed_bytes: int = Field(ge=0, description="Unique known managed working bytes")
    available_bytes: int | None = Field(default=None, ge=0)
    managed_file_count: int = Field(ge=0)
    unrelated_entry_count: int = Field(ge=0)

    model_config = ConfigDict(extra="forbid", frozen=True)


class RecoveryHealth(BaseModel):
    """Integrity result for one authoritative recovery generation."""

    sequence: int = Field(ge=0)
    role: Literal["latest", "previous"]
    valid: bool
    simulated_hour: int | None = Field(default=None, ge=1)
    phase: str | None = None
    error: str | None = None

    model_config = ConfigDict(extra="forbid", frozen=True)


class CheckpointStatusReport(BaseModel):
    """Stable complete report emitted by checkpoint status JSON output."""

    schema_version: Literal["1.0"] = "1.0"
    output_root: str
    state: Literal["active", "resumable", "completed", "absent", "invalid"]
    integrity: Literal["passed", "failed", "not-applicable", "pending"]
    compatibility: Literal["passed", "failed", "not-checked", "not-applicable"]
    simulated_hour: int | None = Field(default=None, ge=1)
    phase: str | None = None
    phase_completed_hours: int | None = Field(default=None, ge=0)
    phase_total_hours: int | None = Field(default=None, ge=1)
    checkpoint_hours: int | None = Field(default=None, ge=0)
    suspended: bool = False
    suspension_requested: bool = False
    used_fallback: bool = False
    resume_command: str | None = None
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    storage: StorageUsage
    recovery_points: tuple[RecoveryHealth, ...] = ()
    diagnostics: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid", frozen=True)


def checkpoint_bundle_root_hint(output_root: Path) -> Path | None:
    """Suggest the parent bundle when given its generated ``data`` directory."""

    requested = Path(output_root)
    if requested.name != "data" or requested.is_symlink():
        return None
    parent = IncrementalCheckpointStore(requested.resolve().parent)
    workspace = parent.workspace
    has_workspace = workspace.is_dir() and not workspace.is_symlink()
    has_completed_bundle = (parent.output_root / GENERATION_MANIFEST_FILENAME).is_file()
    return parent.output_root if has_workspace or has_completed_bundle else None


def _recovery_phase_progress(
    scenario: Scenario,
    recovery: CheckpointRecovery,
) -> tuple[int, int] | None:
    """Return completed and total hours within a resumable hour-based phase."""

    cursor = recovery.manifest.cursor
    if cursor.phase == "warmup":
        warmup = scenario.time_window.warmup
        duration = parse_duration(warmup) if warmup is not None else parse_duration("8h")
        total = max(1, math.ceil(duration.total_seconds() / 3600))
        return cursor.completed_simulated_hours, total
    if cursor.phase != "collection" or cursor.next_hour is None:
        return None
    try:
        start, end = resolve_time_window(scenario.time_window)
        next_hour = datetime.fromisoformat(cursor.next_hour)
        elapsed_seconds = (next_hour - start).total_seconds()
    except (TypeError, ValueError):
        return None
    if elapsed_seconds < 0 or next_hour >= end:
        return None
    total = max(1, math.ceil((end - start).total_seconds() / 3600))
    completed = int(elapsed_seconds // 3600)
    return completed, total


def _managed_files(
    roots: tuple[Path, ...],
    *,
    excluded_root: Path | None = None,
) -> tuple[dict[tuple[int, int], int], list[str]]:
    identities: dict[tuple[int, int], int] = {}
    warnings: list[str] = []
    for root in roots:
        if not root.exists() and not root.is_symlink():
            continue
        candidates = [root] if root.is_file() or root.is_symlink() else root.rglob("*")
        for path in candidates:
            if excluded_root is not None:
                try:
                    path.relative_to(excluded_root)
                except ValueError:
                    pass
                else:
                    continue
            if path.is_symlink():
                warnings.append(f"managed path is a symlink and was not counted: {path}")
                continue
            try:
                info = path.stat()
            except OSError as error:
                warnings.append(f"managed path could not be measured: {path} ({error})")
                continue
            if not path.is_file():
                continue
            identity = (int(info.st_dev), int(info.st_ino))
            identities.setdefault(identity, info.st_size)
    return identities, warnings


def _storage_usage(store: IncrementalCheckpointStore) -> tuple[StorageUsage, tuple[str, ...]]:
    workspace = store.workspace
    staged = store.staged_bundle
    generated_files, warnings = _managed_files((staged,))
    checkpoint_files, checkpoint_warnings = _managed_files(
        (workspace,),
        excluded_root=staged,
    )
    checkpoint_files = {
        identity: size
        for identity, size in checkpoint_files.items()
        if identity not in generated_files
    }
    warnings.extend(checkpoint_warnings)

    published_roots = tuple(
        store.output_root / spec.relative_path
        for spec in SIDECAR_REGISTRY.existing(store.output_root)
    )
    published_files, published_warnings = _managed_files(published_roots)
    published_files = {
        identity: size
        for identity, size in published_files.items()
        if identity not in generated_files and identity not in checkpoint_files
    }
    warnings.extend(published_warnings)
    if not generated_files:
        generated_files = published_files
        published_files = {}
        prior_bundle = 0
    else:
        prior_bundle = sum(published_files.values())

    generated = sum(generated_files.values())
    checkpoint = sum(checkpoint_files.values())
    all_files = generated_files | checkpoint_files | published_files
    known_total = sum(all_files.values())
    try:
        available = shutil.disk_usage(store.output_root).free
    except OSError:
        available = None
    known_names = {store.workspace.name, *(spec.relative_path for spec in SIDECAR_REGISTRY.specs)}
    try:
        unrelated_count = sum(
            1 for path in store.output_root.iterdir() if path.name not in known_names
        )
    except OSError:
        unrelated_count = 0
    usage = StorageUsage(
        generated_bytes=generated,
        checkpoint_bytes=checkpoint,
        recovery_overhead_bytes=checkpoint,
        prior_bundle_bytes=prior_bundle,
        total_managed_bytes=known_total,
        available_bytes=available,
        managed_file_count=len(all_files),
        unrelated_entry_count=unrelated_count,
    )
    return usage, tuple(warnings)


def _compatibility(
    store: IncrementalCheckpointStore,
    recovery: CheckpointRecovery,
) -> tuple[bool, dict[str, Any], str | None]:
    try:
        compiled = compile_scenario(store.resolved_scenario_path(recovery))
        options = recovery.manifest.metadata.get("run_options", {})
        if type(options) is not dict:
            raise ValueError("checkpoint run options are malformed")
        target = options.get("output_target", "default")
        oob = options.get("oob_hosts", [])
        if (
            type(target) is not str
            or type(oob) is not list
            or not all(type(item) is str for item in oob)
        ):
            raise ValueError("checkpoint run options are malformed")
        formats = [
            str(log["format"])
            for log in compiled.scenario.output.logs
            if isinstance(log, dict) and "format" in log
        ]
        actual = run_fingerprint(
            compiled,
            output_target=target,
            formats=formats,
            oob_hosts=tuple(oob),
        )
        current_components = run_fingerprint_components(
            compiled,
            output_target=target,
            formats=formats,
            oob_hosts=tuple(oob),
        )
    except (CheckpointError, EvidenceForgeError, OSError, ValueError) as error:
        return False, {}, f"runtime compatibility could not be evaluated: {error}"
    stored_components = recovery.manifest.metadata.get("fingerprint_components", {})
    diagnostics = {
        "stored_fingerprint": recovery.manifest.run_fingerprint,
        "current_fingerprint": actual,
        "stored_components": stored_components,
        "current_components": current_components,
    }
    phase_progress = _recovery_phase_progress(compiled.scenario, recovery)
    if phase_progress is not None:
        diagnostics["phase_completed_hours"] = phase_progress[0]
        diagnostics["phase_total_hours"] = phase_progress[1]
    if type(stored_components) is dict:
        diagnostics["component_mismatches"] = {
            key: {"stored": stored_components.get(key), "current": current_components.get(key)}
            for key in sorted(set(stored_components) | set(current_components))
            if stored_components.get(key) != current_components.get(key)
        }
    try:
        with effective_config_scope(compiled.effective_config):
            forecast = build_resource_forecast(
                compiled.scenario,
                estimate_workload(
                    compiled.scenario,
                    scenario_root=store.resolved_scenario_path(recovery).parent,
                ),
                store.output_root,
                checkpoint_hours=recovery.manifest.checkpoint_hours,
            )
        diagnostics["checkpoint_workspace_forecast"] = forecast.checkpoint_workspace.model_dump(
            mode="json"
        )
    except (EvidenceForgeError, OSError, ValueError) as error:
        diagnostics["checkpoint_workspace_forecast_error"] = str(error)
    return actual == recovery.manifest.run_fingerprint, diagnostics, None


def inspect_checkpoint(output_root: Path) -> CheckpointStatusReport:
    """Build a thorough report without creating, deleting, or rewriting any path."""

    started = time.monotonic()
    store = _InspectingCheckpointStore(output_root)
    warnings: list[str] = []
    errors: list[str] = []
    diagnostics: dict[str, Any] = {}

    if not store.workspace.exists():
        if (store.output_root / GENERATION_MANIFEST_FILENAME).is_file():
            storage, storage_warnings = _storage_usage(store)
            warnings.extend(storage_warnings)
            try:
                manifest = verify_generation_bundle(store.output_root)
            except (OSError, ValueError, EvidenceForgeError, CheckpointError) as error:
                errors.append(f"completed bundle validation failed: {error}")
                state: Literal["completed", "invalid"] = "invalid"
                integrity: Literal["passed", "failed"] = "failed"
            else:
                state = "completed"
                integrity = "passed"
                diagnostics["generation_manifest"] = manifest
            diagnostics["validation_seconds"] = time.monotonic() - started
            return CheckpointStatusReport(
                output_root=str(store.output_root),
                state=state,
                integrity=integrity,
                compatibility="not-applicable",
                errors=tuple(errors),
                warnings=tuple(warnings),
                storage=storage,
                diagnostics=diagnostics,
            )
        suggested_root = checkpoint_bundle_root_hint(output_root)
        if suggested_root is not None:
            warnings.append(
                f"This appears to be the generated data directory. Use the bundle root instead: "
                f"eforge checkpoint status {suggested_root}"
            )
        diagnostics["validation_seconds"] = time.monotonic() - started
        return CheckpointStatusReport(
            output_root=str(store.output_root),
            state="absent",
            integrity="not-applicable",
            compatibility="not-applicable",
            warnings=tuple(warnings),
            storage=StorageUsage(
                generated_bytes=0,
                checkpoint_bytes=0,
                recovery_overhead_bytes=0,
                prior_bundle_bytes=0,
                total_managed_bytes=0,
                available_bytes=None,
                managed_file_count=0,
                unrelated_entry_count=0,
            ),
            diagnostics=diagnostics,
        )

    storage, storage_warnings = _storage_usage(store)
    warnings.extend(storage_warnings)
    lock = store.lock.inspect()
    diagnostics["lock"] = {
        "state": lock.state,
        "owner": lock.owner,
        "detail": lock.detail,
        "heartbeat": "not used; local liveness is process-probed",
    }
    diagnostics["filesystem"] = {
        "ownership_and_no_symlink_validation": "performed",
        "durability_probe": "not repeated by read-only status; required when generation starts",
    }
    if lock.state == "stale" and lock.detail:
        warnings.append(lock.detail)
    elif lock.state == "invalid" and lock.detail:
        errors.append(lock.detail)

    selected: CheckpointRecovery | None = None
    recovery_health: list[RecoveryHealth] = []
    try:
        entries = store.recovery_index_entries(read_only=True)
    except CheckpointError as error:
        entries = ()
        errors.append(str(error))
    for index, (sequence, digest) in enumerate(entries):
        try:
            candidate = store.validate_recovery_entry(sequence, digest)
        except CheckpointError as error:
            recovery_health.append(
                RecoveryHealth(
                    sequence=sequence,
                    role="latest" if index == 0 else "previous",
                    valid=False,
                    error=str(error),
                )
            )
            warnings.append(f"recovery {sequence} is invalid: {error}")
            continue
        recovery_health.append(
            RecoveryHealth(
                sequence=sequence,
                role="latest" if index == 0 else "previous",
                valid=True,
                simulated_hour=candidate.manifest.cursor.completed_simulated_hours,
                phase=candidate.manifest.cursor.phase,
            )
        )
        if selected is None:
            selected = candidate.model_copy(update={"used_fallback": index > 0})

    controller = None
    suspended = None
    requested = None
    try:
        controller = read_controller_record(store)
        suspended = read_suspension_record(store)
        requested = read_suspension_request(store)
    except CheckpointError as error:
        errors.append(str(error))

    active = lock.state in {"active", "remote"}
    if selected is None:
        if entries:
            errors.append("no valid generation checkpoint remains")
            state_value: Literal["active", "invalid"] = "invalid"
            integrity_value: Literal["failed", "pending"] = "failed"
        elif active:
            state_value = "active"
            integrity_value = "pending"
        else:
            errors.append("no generation checkpoint exists")
            state_value = "invalid"
            integrity_value = "failed"
        diagnostics["validation_seconds"] = time.monotonic() - started
        return CheckpointStatusReport(
            output_root=str(store.output_root),
            state=state_value,
            integrity=integrity_value,
            compatibility="not-checked",
            checkpoint_hours=None if controller is None else controller.checkpoint_hours,
            suspension_requested=requested is not None,
            warnings=tuple(warnings),
            errors=tuple(errors),
            storage=storage,
            recovery_points=tuple(recovery_health),
            diagnostics=diagnostics,
        )

    compatible, compatibility_diagnostics, compatibility_error = _compatibility(store, selected)
    diagnostics.update(compatibility_diagnostics)
    forecast = diagnostics.get("checkpoint_workspace_forecast")
    if isinstance(forecast, dict) and type(forecast.get("expected_bytes")) is int:
        expected = forecast["expected_bytes"]
        diagnostics["checkpoint_workspace_forecast_vs_actual"] = {
            "expected_bytes": expected,
            "actual_bytes": storage.checkpoint_bytes,
            "actual_to_expected_ratio": (
                None if expected == 0 else storage.checkpoint_bytes / expected
            ),
        }
    if compatibility_error:
        errors.append(compatibility_error)
    if selected.used_fallback:
        warnings.append("newest recovery is invalid; the previous recovery will be used")
    if not compatible:
        errors.append("checkpoint fingerprint does not match this EvidenceForge runtime")
    if (
        storage.available_bytes is not None
        and storage.available_bytes < storage.recovery_overhead_bytes
    ):
        warnings.append("available disk is smaller than the current recovery overhead")
    cursor = selected.manifest.cursor
    phase_completed_hours = diagnostics.get("phase_completed_hours")
    phase_total_hours = diagnostics.get("phase_total_hours")
    diagnostics.update(
        {
            "run_id": selected.manifest.run_id,
            "checkpoint_schema": selected.manifest.schema_version,
            "selected_sequence": selected.manifest.sequence,
            "participant_heads": len(selected.manifest.participant_heads),
            "segment_count": len(selected.segments),
            "segment_bytes": sum(segment.size for segment in selected.segments),
            "validation_seconds": time.monotonic() - started,
            "validation_bytes_hashed": store.validation_bytes_hashed,
            "workspace_bytes": storage.checkpoint_bytes,
        }
    )
    state = (
        "invalid"
        if not compatible or lock.state == "invalid"
        else ("active" if active else "resumable")
    )
    return CheckpointStatusReport(
        output_root=str(store.output_root),
        state=state,
        integrity="passed",
        compatibility="passed" if compatible else "failed",
        simulated_hour=cursor.completed_simulated_hours,
        phase=cursor.phase,
        phase_completed_hours=(
            phase_completed_hours if type(phase_completed_hours) is int else None
        ),
        phase_total_hours=phase_total_hours if type(phase_total_hours) is int else None,
        checkpoint_hours=selected.manifest.checkpoint_hours,
        suspended=suspended is not None and not active,
        suspension_requested=requested is not None,
        used_fallback=selected.used_fallback,
        resume_command=(
            f"eforge generate --output {store.output_root} --resume"
            if compatible and not active
            else None
        ),
        warnings=tuple(warnings),
        errors=tuple(errors),
        storage=storage,
        recovery_points=tuple(recovery_health),
        diagnostics=diagnostics,
    )


__all__ = [
    "CheckpointStatusReport",
    "RecoveryHealth",
    "StorageUsage",
    "checkpoint_bundle_root_hint",
    "inspect_checkpoint",
]
