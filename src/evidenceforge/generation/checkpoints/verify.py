"""Isolated full-hydration verification for one generation checkpoint."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.composition import compile_scenario
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.output_targets import normalize_output_target

from .errors import CheckpointCompatibilityError, CheckpointError
from .fingerprint import (
    classify_resume_compatibility,
    run_fingerprint,
    run_fingerprint_components,
)
from .runtime import IncrementalCheckpointController
from .store import IncrementalCheckpointStore


class CheckpointVerifyReport(BaseModel):
    """Stable result from isolated participant hydration."""

    schema_version: Literal["1.0"] = "1.0"
    output_root: str
    selected_sequence: int = Field(ge=0)
    simulated_hour: int = Field(ge=1)
    phase: str
    compatibility_level: Literal["exact", "load-compatible"]
    output_equivalence: Literal["exact", "not-guaranteed"]
    restore_verified: Literal[True] = True
    participant_count: int = Field(ge=1)
    dangling_process_parent_count: int = Field(ge=0)
    dangling_process_parents: list[dict[str, str]] = Field(default_factory=list)
    component_mismatches: dict[str, dict[str, Any]] = Field(default_factory=dict)
    warnings: tuple[str, ...] = ()

    model_config = ConfigDict(extra="forbid", frozen=True)


def verify_checkpoint_recovery(output_root: Path) -> CheckpointVerifyReport:
    """Fully hydrate a checkpoint into scratch storage without changing its bundle."""

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
        hydration = engine.verify_checkpoint_recovery()

    warnings: tuple[str, ...] = ()
    if compatibility.level == "load-compatible":
        warnings = (
            "serialized state hydrated under a different EvidenceForge build; remaining output "
            "equivalence is not guaranteed",
        )
    return CheckpointVerifyReport(
        output_root=str(source_store.output_root),
        selected_sequence=recovery.manifest.sequence,
        simulated_hour=recovery.manifest.cursor.completed_simulated_hours,
        phase=recovery.manifest.cursor.phase,
        compatibility_level=compatibility.level,
        output_equivalence=compatibility.output_equivalence,
        participant_count=int(hydration["participant_count"]),
        dangling_process_parent_count=int(hydration["dangling_process_parent_count"]),
        dangling_process_parents=list(hydration["dangling_process_parents"]),
        component_mismatches=compatibility.component_mismatches,
        warnings=warnings,
    )


__all__ = ["CheckpointVerifyReport", "verify_checkpoint_recovery"]
