"""Verify the complete corrected-reference matrix and record final raw artifact hashes."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
from pathlib import Path
from typing import Any

import yaml
from compare_cleanup_output import snapshot
from report_cleanup_correction import raw_hashes
from verify_cleanup_resume import compare_resumed


def main() -> None:
    """Refuse missing cases, evidence differences, invalid provenance or incorrect hashes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--candidate-prefix", default="pass2-final", help="Prefix of immutable completed captures"
    )
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    behavior = yaml.safe_load(
        (repository / "src/evidenceforge/config/generation_behavior.yaml").read_text()
    )
    groups = (
        ("core", "pass2-item1-core-final", 32),
        ("typed", "pass2-item1-typed-friction", 6),
        ("periodic", "pass2-item1-periodic-final", 6),
        ("shell", "pass2-item1-foreground-2", 6),
        ("foreground", "pass2-native-corrected-final", 36),
        ("process", "pass2-process-before-final", 36),
    )
    comparisons: list[dict[str, Any]] = []
    for group, baseline_name, count in groups:
        baseline = args.evidence_root / baseline_name
        candidate = args.evidence_root / f"{args.candidate_prefix}-{group}"
        names = {path.name for path in baseline.iterdir() if path.is_dir()}
        final_names = {path.name for path in candidate.iterdir() if path.is_dir()}
        if len(names) != count or names != final_names:
            raise ValueError(f"Incomplete {group} matrix: expected {count} cases")
        for name in sorted(names):
            before, after = snapshot(baseline / name), snapshot(candidate / name)
            if not before or before != after:
                raise ValueError(f"Evidence differs: {group}/{name}")
            preceding = args.evidence_root / f"pass2-item6c-{group}" / name
            if preceding.is_dir() and snapshot(preceding) != after:
                raise ValueError(f"Evidence differs from preceding process substep: {name}")
            comparisons.append(
                {
                    "group": group,
                    "case": name,
                    "reference": baseline_name,
                    "preceding_substep_compared": preceding.is_dir(),
                    "comparison_sha256": after,
                    "raw_file_sha256": raw_hashes(candidate / name),
                }
            )
    if len(comparisons) != 122:
        raise ValueError("Incomplete expanded acceptance matrix")
    checkpoints = args.evidence_root / f"{args.candidate_prefix}-checkpoints"
    changes = [change["id"] for change in behavior["changes"] if change["revision"] > 42]
    resumed_cases: list[dict[str, Any]] = []
    for target in ("default", "sof-elk", "splunk"):
        for seed in (42, 137):
            name = f"{target}-{seed}"
            control = checkpoints / f"control-{name}"
            for policy, same_build in (("compatible", False), ("exact", True)):
                resumed = checkpoints / f"{policy}-{name}"
                compare_resumed(
                    control,
                    resumed,
                    same_build=same_build,
                    expected_change_ids=[] if same_build else changes,
                )
                resumed_cases.append(
                    {
                        "case": f"{policy}-{name}",
                        "original_build": not same_build,
                        "raw_file_sha256": raw_hashes(resumed),
                        "control_raw_file_sha256": raw_hashes(control),
                    }
                )
    references = (
        "docs/worklog/2026-09-12-corrected-evidence-reference.json",
        "docs/worklog/2026-09-12-process-evidence-reference.json",
        "scripts/fixtures/cleanup-inputs.json",
        "scripts/fixtures/cleanup-native-inputs.json",
        "uv.lock",
    )
    report = {
        "behavior_revision": behavior["current_revision"],
        "behavior_surface_sha256": behavior["behavior_surface_sha256"],
        "python_version": platform.python_version(),
        "original_commit": "e4035435e8e53400ab25a74fe551313354369203",
        "first_pass_commit": "2c7dee2a8a779d26b2d5ecc56aeae09ff7d1c546",
        "corrected_reference_commit": "ffdce735",
        "reference_sha256": {
            name: hashlib.sha256((repository / name).read_bytes()).hexdigest()
            for name in references
        },
        "comparison_policy": (
            "Evidence and ground-truth file sets and raw bytes must match the accepted correction. "
            "No record, timestamp or identifier normalization. Existing generation.log and field-level "
            "manifest provenance exceptions only. Manifest-listed file hashes are verified. "
            "Raw manifest hashes are retained separately from structural comparison hashes."
        ),
        "comparisons": comparisons,
        "resumes": resumed_cases,
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"PASS: {len(comparisons)} byte comparisons and {len(resumed_cases)} checkpoint resumes")


if __name__ == "__main__":
    main()
