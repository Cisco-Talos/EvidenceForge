"""Persist the frozen evidence hashes and verified checkpoint matrix for cleanup review."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
from pathlib import Path
from typing import Any

from compare_cleanup_output import snapshot
from verify_cleanup_resume import compare_resumed


def main() -> None:
    """Refuse incomplete matrices or differences before writing the acceptance artifact."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    comparisons: list[dict[str, Any]] = []
    groups = (
        ("baseline", "final", 32),
        ("supplement-baseline", "supplement-final", 6),
        ("periodic-baseline", "periodic-final", 6),
    )
    for original, candidate, expected_count in groups:
        baseline = args.evidence_root / original
        directories = sorted(path for path in baseline.iterdir() if path.is_dir())
        if len(directories) != expected_count:
            raise ValueError(f"Incomplete frozen matrix: {original}")
        for directory in directories:
            expected = snapshot(directory)
            actual = snapshot(args.evidence_root / candidate / directory.name)
            if not expected or expected != actual:
                raise ValueError(f"Evidence differs: {directory.name}")
            root_hash = hashlib.sha256(json.dumps(expected, sort_keys=True).encode()).hexdigest()
            comparisons.append(
                {
                    "case": directory.name,
                    "artifacts": len(expected),
                    "snapshot_sha256": root_hash,
                    "expected_file_hashes": expected,
                }
            )
    checkpoint_root = args.evidence_root / "final-checkpoints"
    checkpoint_cases: list[str] = []
    changes: list[str] | None = None
    build: dict[str, Any] = {}
    for target in ("default", "sof-elk", "splunk"):
        for seed in (42, 137):
            name = f"{target}-{seed}"
            control = checkpoint_root / f"control-{name}"
            compatible = checkpoint_root / f"compatible-{name}"
            compare_resumed(control, compatible)
            compare_resumed(
                control, checkpoint_root / f"exact-{name}", same_build=True, expected_change_ids=[]
            )
            rejection = compatible.with_suffix(".exact-rejection.log").read_text()
            if "requires the complete original fingerprint" not in " ".join(rejection.split()):
                raise ValueError(f"Missing exact-build rejection: {name}")
            provenance = json.loads((compatible / "GENERATION_MANIFEST.json").read_text())[
                "resume_provenance"
            ]
            transition_changes = provenance["transitions"][0]["behavior_change_ids"]
            if changes is not None and transition_changes != changes:
                raise ValueError("Checkpoint cases did not use the same behavior history")
            changes = transition_changes
            if build and build != provenance["current_build"]:
                raise ValueError("Checkpoint cases did not use the same candidate build")
            build = provenance["current_build"]
            checkpoint_cases.append(name)
    report = {
        "baseline_commit": "e4035435e8e53400ab25a74fe551313354369203",
        "candidate_build": build,
        "python_version": platform.python_version(),
        "dependency_lock_sha256": hashlib.sha256(
            (Path(__file__).resolve().parents[1] / "uv.lock").read_bytes()
        ).hexdigest(),
        "fixture_sha256": json.loads(
            (Path(__file__).parent / "fixtures" / "cleanup-inputs.json").read_text()
        ),
        "behavior_revision": 48,
        "behavior_changes": changes,
        "evidence_comparison": "Raw file sets and bytes; no record or timestamp normalization",
        "exceptions": {
            "generation.log": "Runtime diagnostics are excluded",
            "GENERATION_MANIFEST.json": "Structured comparison: created_at and validated resume lineage/seed-adoption bookkeeping",
        },
        "comparisons": comparisons,
        "original_and_same_build_checkpoint_cases": checkpoint_cases,
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"PASS: {len(comparisons)} evidence cases and {2 * len(checkpoint_cases)} resumes")


if __name__ == "__main__":
    main()
