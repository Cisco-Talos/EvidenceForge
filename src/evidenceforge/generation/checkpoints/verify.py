"""Isolated full-hydration verification for one generation checkpoint."""

from __future__ import annotations

import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.composition import compile_scenario
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.output_targets import normalize_output_target

from .errors import CheckpointCompatibilityError, CheckpointError
from .fingerprint import classify_resume_compatibility, run_fingerprint, run_fingerprint_components
from .runtime import IncrementalCheckpointController
from .store import IncrementalCheckpointStore

VerifyProgress = Callable[[str, dict[str, object]], None]


class CheckpointVerifyReport(BaseModel):
    """Stable result from isolated participant hydration."""

    schema_version: Literal["1.1"] = "1.1"
    output_root: str
    selected_sequence: int = Field(ge=0)
    simulated_hour: int = Field(ge=1)
    phase: str
    compatibility_level: Literal["exact", "load-compatible"]
    output_equivalence: Literal["exact", "not-guaranteed"]
    restore_verified: Literal[True] = True
    run_identity: Literal["matched", "mismatched", "not-checked"] = "matched"
    loadability: Literal["verified"] = "verified"
    behavior_change: Literal["exact", "none-declared", "localized", "material", "unknown"] = "exact"
    confirmation_required: bool = False
    participant_count: int = Field(ge=1)
    dangling_process_parent_count: int = Field(ge=0)
    dangling_process_parents: list[dict[str, str]] = Field(default_factory=list)
    component_mismatches: dict[str, dict[str, Any]] = Field(default_factory=dict)
    run_differences: dict[str, dict[str, Any]] = Field(default_factory=dict)
    runtime_differences: dict[str, dict[str, Any]] = Field(default_factory=dict)
    behavior_differences: dict[str, dict[str, Any]] = Field(default_factory=dict)
    state_contract_differences: dict[str, dict[str, Any]] = Field(default_factory=dict)
    behavior_change_ids: tuple[str, ...] = ()
    behavior_domains: tuple[str, ...] = ()
    behavior_formats: tuple[str, ...] = ()
    behavior_summaries: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    model_config = ConfigDict(extra="forbid", frozen=True)


def _notify(progress: VerifyProgress | None, phase: str, **detail: object) -> None:
    if progress is not None:
        progress(phase, detail)


def verify_checkpoint_recovery(
    output_root: Path,
    *,
    verbose: bool = False,
    progress: VerifyProgress | None = None,
) -> CheckpointVerifyReport:
    """Fully hydrate a checkpoint into scratch storage without changing its bundle."""

    _notify(progress, "integrity")
    source_store = IncrementalCheckpointStore(output_root)
    recovery = source_store.recover(read_only=True)
    resolved_path = source_store.resolved_scenario_path(recovery)
    compiled = compile_scenario(resolved_path)
    options = recovery.manifest.metadata.get("run_options", {})
    if type(options) is not dict:
        raise CheckpointError("checkpoint run options are malformed")
    target_value = options.get("output_target", "default")
    oob_value = options.get("oob_hosts", [])
    if (
        type(target_value) is not str
        or type(oob_value) is not list
        or any(type(value) is not str for value in oob_value)
    ):
        raise CheckpointError("checkpoint run options are malformed")
    target = normalize_output_target(target_value)
    oob_hosts = tuple(oob_value)
    formats = [
        str(log["format"])
        for log in compiled.scenario.output.logs
        if isinstance(log, dict) and "format" in log
    ]
    current_fingerprint = run_fingerprint(
        compiled,
        output_target=target.value,
        formats=formats,
        oob_hosts=oob_hosts,
    )
    current_components = run_fingerprint_components(
        compiled,
        output_target=target.value,
        formats=formats,
        oob_hosts=oob_hosts,
    )
    compatibility = classify_resume_compatibility(
        stored_fingerprint=recovery.manifest.run_fingerprint,
        current_fingerprint=current_fingerprint,
        stored_components=recovery.manifest.metadata.get("fingerprint_components", {}),
        current_components=current_components,
        authoritative_resolved_scenario=True,
    )
    if not compatibility.can_resume:
        detail = compatibility.reason or "hard compatibility fields differ"
        if compatibility.hard_mismatches:
            detail += f" ({', '.join(compatibility.hard_mismatches)})"
        raise CheckpointCompatibilityError(detail)

    with tempfile.TemporaryDirectory(prefix="eforge-checkpoint-verify-") as temporary:
        scratch_root = Path(temporary) / "bundle"
        scratch_store = IncrementalCheckpointStore(scratch_root)
        controller = IncrementalCheckpointController.for_recovery(
            store=scratch_store,
            recovery=recovery,
            fingerprint=current_fingerprint,
            resolved_scenario=source_store.read_resolved_scenario(recovery),
            checkpoint_hours=0,
            fingerprint_components=current_components,
            compatibility_level=compatibility.level,
            recovery_store=source_store,
            behavior_change=compatibility.behavior_change,
            behavior_change_ids=compatibility.behavior_change_ids,
            runtime_differences=compatibility.runtime_differences,
            confirmation_status="verification-read-only",
        )
        engine = GenerationEngine(
            scenario=compiled.scenario,
            output_dir=scratch_root / "data",
            ground_truth_dir=scratch_root,
            artifact_dir=scratch_root / "artifacts",
            scenario_root=resolved_path.parent,
            output_target=target,
            oob_hosts=oob_hosts,
            generation_seed=compiled.scenario.generation_seed,
            allow_large_workload=True,
            compiled_scenario=compiled,
            checkpoint_hours=0,
            checkpoint_controller=controller,
            checkpoint_recovery=recovery,
        )
        hydration = engine.verify_checkpoint_recovery(progress=progress)
    _notify(progress, "completion")

    warnings: list[str] = []
    if compatibility.level == "load-compatible":
        warnings.append(
            "serialized state hydrated under build or runtime drift; remaining output "
            "equivalence is not guaranteed"
        )
    if compatibility.confirmation_required:
        warnings.append(
            f"EvidenceForge behavior change is {compatibility.behavior_change}; compatible "
            "resume requires confirmation, or explicit --resume-policy attempt"
        )
    dangling = list(hydration["dangling_process_parents"]) if verbose else []
    return CheckpointVerifyReport(
        output_root=str(source_store.output_root),
        selected_sequence=recovery.manifest.sequence,
        simulated_hour=recovery.manifest.cursor.completed_simulated_hours,
        phase=recovery.manifest.cursor.phase,
        compatibility_level=compatibility.level,
        output_equivalence=compatibility.output_equivalence,
        run_identity=compatibility.run_identity,
        behavior_change=compatibility.behavior_change,
        confirmation_required=compatibility.confirmation_required,
        participant_count=int(hydration["participant_count"]),
        dangling_process_parent_count=int(hydration["dangling_process_parent_count"]),
        dangling_process_parents=dangling,
        component_mismatches=compatibility.component_mismatches,
        run_differences=compatibility.run_differences,
        runtime_differences=compatibility.runtime_differences,
        behavior_differences=compatibility.behavior_differences,
        state_contract_differences=compatibility.state_contract_differences,
        behavior_change_ids=compatibility.behavior_change_ids,
        behavior_domains=compatibility.behavior_domains,
        behavior_formats=compatibility.behavior_formats,
        behavior_summaries=compatibility.behavior_summaries,
        warnings=tuple(warnings),
    )


__all__ = ["CheckpointVerifyReport", "VerifyProgress", "verify_checkpoint_recovery"]
