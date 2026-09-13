"""Freeze reviewed foreground-correction evidence without replacing original goldens."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
from pathlib import Path
from typing import Any

import yaml
from compare_cleanup_output import snapshot
from verify_cleanup_resume import compare_resumed


def raw_hashes(root: Path) -> dict[str, str]:
    """Record actual file hashes, including the unmodified provenance manifest."""
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.relative_to(root).as_posix() != "generation.log"
    }


def main() -> None:
    """Require complete controls and the reviewed scope of intentional differences."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    behavior = yaml.safe_load(
        (repository / "src/evidenceforge/config/generation_behavior.yaml").read_text()
    )
    if behavior["current_revision"] != 50:
        raise ValueError("Correction reference must be frozen at revision 50")
    comparisons: list[dict[str, Any]] = []
    groups = (
        ("core", "baseline", "pass2-item1-core-final", 32),
        ("typed", "supplement-baseline", "pass2-item1-typed-friction", 6),
        ("periodic", "periodic-baseline", "pass2-item1-periodic-final", 6),
        ("shell", "pass2-foreground-original-2", "pass2-item1-foreground-2", 6),
        ("native", "pass2-native-original-final", "pass2-native-corrected-final", 36),
    )
    changed_core = 0
    for group, baseline, corrected, count in groups:
        before, after = args.evidence_root / baseline, args.evidence_root / corrected
        directories = sorted(path for path in before.iterdir() if path.is_dir())
        if len(directories) != count or len([p for p in after.iterdir() if p.is_dir()]) != count:
            raise ValueError(f"Incomplete {group} comparison")
        for directory in directories:
            candidate = after / directory.name
            original, accepted = snapshot(directory), snapshot(candidate)
            changed = sorted(
                name
                for name in original.keys() | accepted.keys()
                if original.get(name) != accepted.get(name)
            )
            if not accepted or original.keys() != accepted.keys():
                raise ValueError(f"Unexpected evidence file set: {directory.name}")
            if changed and group not in {"core", "native"}:
                raise ValueError(f"Unaffected fixture changed: {directory.name}")
            if group == "core" and changed:
                changed_core += 1
                if any(
                    not name.startswith(("LINUX-01.", "MAIL-01.", "WEB-01.", "SAMBA-01."))
                    or not name.endswith(("/ecar.json", "/syslog.log"))
                    for name in changed
                ):
                    raise ValueError(
                        f"Difference outside reviewed Linux lifecycle evidence: {changed}"
                    )
            if group == "native" and any(
                name not in {"GROUND_TRUTH.json", "LNX-01/ecar.json"} for name in changed
            ):
                raise ValueError(f"Unexpected native fixture difference: {changed}")
            record: dict[str, Any] = {
                "group": group,
                "case": directory.name,
                "changed_files": changed,
                "original_comparison_hashes": original,
                "accepted_comparison_hashes": accepted,
                "original_raw_file_sha256": raw_hashes(directory),
                "accepted_raw_file_sha256": raw_hashes(candidate),
            }
            if group == "native":
                first_pass = args.evidence_root / "pass2-native-first-pass-final" / directory.name
                record["first_pass_comparison_hashes"] = snapshot(first_pass)
                record["first_pass_raw_file_sha256"] = raw_hashes(first_pass)
                record["native_trace"] = {
                    name: json.loads((root / "GROUND_TRUTH.json").read_text())
                    for name, root in (
                        ("original", directory),
                        ("first_pass", first_pass),
                        ("corrected", candidate),
                    )
                }
            comparisons.append(record)
    if changed_core != 8:
        raise ValueError(f"Expected exactly eight reviewed core differences, got {changed_core}")
    checkpoint_root = args.evidence_root / "pass2-item1-checkpoints"
    checkpoint_cases = []
    for target in ("default", "sof-elk", "splunk"):
        for seed in (42, 137):
            name = f"{target}-{seed}"
            control = checkpoint_root / f"control-{name}"
            compare_resumed(control, checkpoint_root / f"compatible-{name}")
            compare_resumed(control, checkpoint_root / f"exact-{name}", same_build=True)
            checkpoint_cases.append(name)
    report = {
        "original_commit": "e4035435e8e53400ab25a74fe551313354369203",
        "first_pass_commit": "2c7dee2a8a779d26b2d5ecc56aeae09ff7d1c546",
        "behavior_revision": behavior["current_revision"],
        "behavior_surface_sha256": behavior["behavior_surface_sha256"],
        "python_version": platform.python_version(),
        "dependency_lock_sha256": hashlib.sha256((repository / "uv.lock").read_bytes()).hexdigest(),
        "frozen_fixture_sha256": json.loads(
            (repository / "scripts/fixtures/cleanup-inputs.json").read_text()
        ),
        "native_driver_sha256": hashlib.sha256(
            (repository / "scripts/cleanup_foreground_contract.py").read_bytes()
        ).hexdigest(),
        "intentional_difference": "Foreground ownership lasts until modeled release; earlier actual termination supersedes its reservation. See the focused worklog for three-build native evidence and per-case attribution.",
        "comparison_policy": "Raw file sets and bytes. Only generation.log is excluded; GENERATION_MANIFEST.json uses the existing created_at/provenance allowlist and verifies recorded file hashes. Raw manifest hashes are also retained here.",
        "comparisons": comparisons,
        "original_and_same_build_checkpoint_cases": checkpoint_cases,
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"Frozen {len(comparisons)} corrected reference cases and 12 verified resumes")


if __name__ == "__main__":
    main()
