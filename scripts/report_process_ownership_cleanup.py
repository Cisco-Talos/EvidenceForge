"""Verify all final process-cleanup controls and record their actual artifact hashes."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any

import yaml
from compare_cleanup_output import snapshot
from report_cleanup_correction import raw_hashes
from verify_cleanup_resume import compare_resumed

GROUPS = {
    "core": ("pass2-final2-core", 32),
    "typed": ("pass2-final2-typed", 6),
    "periodic": ("pass2-final2-periodic", 6),
    "shell": ("pass2-final2-shell", 6),
    "foreground": ("pass2-final2-foreground", 36),
    "process": ("pass2-final2-process", 36),
    "parent-preflight": ("pass3-parent-preflight-baseline", 72),
}


def structural_inventory(repository: Path) -> dict[str, Any]:
    """Measure current implementation ownership and every frozen forwarding site."""
    support = repository / "src/evidenceforge/generation/actions/process_support"
    generator = ast.parse(
        (repository / "src/evidenceforge/generation/activity/generator.py").read_text()
    )
    functions = {
        node.name: node
        for cls in generator.body
        if isinstance(cls, ast.ClassDef) and cls.name == "ActivityGenerator"
        for node in cls.body
        if isinstance(node, ast.FunctionDef)
    }
    baseline = json.loads(
        (repository / "docs/worklog/2026-09-12-process-cleanup-baseline.json").read_text()
    )
    remaining: dict[str, int] = {}
    for entry in baseline["forwarding_callers"]:
        names = {call["method"] for call in entry["calls"]}
        remaining[entry["caller"]] = sum(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "self"
            and node.func.attr in names
            for node in ast.walk(functions[entry["caller"]])
        )
    implementations: dict[str, Any] = {}
    for path in sorted(support.glob("*.py")):
        if path.stem not in {
            "parents",
            "parent_windows",
            "parent_linux",
            "parent_history",
            "preflight",
        }:
            continue
        tree = ast.parse(path.read_text())
        implementations[path.stem] = {
            cls.name: {
                "fields": {
                    node.target.id: ast.unparse(node.annotation)
                    for node in cls.body
                    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
                },
                "operations": {
                    node.name: node.end_lineno - node.lineno + 1
                    for node in cls.body
                    if isinstance(node, ast.FunctionDef)
                },
            }
            for cls in tree.body
            if isinstance(cls, ast.ClassDef)
        }
    hooks = (
        "_preflight_bounded_process_source_deadline",
        "_plan_process_execution_effects",
        "_plan_process_execution_side_effects",
        "_process_endpoint_effect_rng",
        "_plan_process_provisional_termination",
        "_plan_process_lifetime",
        "_cancel_uncommitted_process_artifact_publications",
    )
    return {
        "baseline_forwarding_calls": 35,
        "remaining_forwarding_calls": remaining,
        "owners": implementations,
        "generator_preflight_hooks": {
            name: {
                "lines": functions[name].end_lineno - functions[name].lineno + 1,
                "statements": [type(node).__name__ for node in functions[name].body],
            }
            for name in hooks
        },
    }


def main() -> None:
    """Reject missing controls, drift or invalid provenance before producing a report."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--candidate-prefix", required=True)
    parser.add_argument("--previous-prefix")
    parser.add_argument("--checkpoints", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    behavior = yaml.safe_load(
        (repository / "src/evidenceforge/config/generation_behavior.yaml").read_text()
    )
    comparisons: list[dict[str, Any]] = []
    for group, (baseline_name, count) in GROUPS.items():
        baseline = args.evidence_root / baseline_name
        candidate = args.evidence_root / f"{args.candidate_prefix}-{group}"
        names = {p.name for p in baseline.iterdir() if p.is_dir()}
        if len(names) != count or names != {p.name for p in candidate.iterdir() if p.is_dir()}:
            raise ValueError(f"Incomplete {group} matrix")
        for name in sorted(names):
            actual = snapshot(candidate / name)
            if not actual or actual != snapshot(baseline / name):
                raise ValueError(f"Evidence differs from 010ae90f: {group}/{name}")
            if args.previous_prefix:
                previous = args.evidence_root / f"{args.previous_prefix}-{group}" / name
                if snapshot(previous) != actual:
                    raise ValueError(f"Evidence differs from preceding item: {group}/{name}")
            comparisons.append(
                {
                    "group": group,
                    "case": name,
                    "reference": baseline_name,
                    "comparison_sha256": actual,
                    "raw_file_sha256": raw_hashes(candidate / name),
                }
            )
    assert len(comparisons) == 194
    resumes: list[dict[str, Any]] = []
    if args.checkpoints:
        for target in ("default", "sof-elk", "splunk"):
            for seed in (42, 137):
                name = f"{target}-{seed}"
                control = args.checkpoints / f"control-{name}"
                for kind, revision, same_build in (
                    ("compatible", 42, False),
                    ("compatible-baseline", 58, False),
                    ("exact", behavior["current_revision"], True),
                ):
                    resumed = args.checkpoints / f"{kind}-{name}"
                    expected = [
                        change["id"]
                        for change in behavior["changes"]
                        if change["revision"] > revision
                    ]
                    compare_resumed(
                        control, resumed, same_build=same_build, expected_change_ids=expected
                    )
                    resumes.append(
                        {
                            "case": f"{kind}-{name}",
                            "origin_revision": revision,
                            "raw_file_sha256": raw_hashes(resumed),
                            "control_raw_file_sha256": raw_hashes(control),
                        }
                    )
    references = (
        "docs/worklog/2026-09-12-process-cleanup-baseline.json",
        "docs/worklog/2026-09-12-parent-preflight-reference.json",
        "docs/worklog/2026-09-12-second-pass-evidence.json",
        "scripts/fixtures/cleanup-inputs.json",
        "scripts/fixtures/cleanup-native-inputs.json",
        "uv.lock",
    )
    report = {
        "baseline_commit": "010ae90ff3dc345d5f05224345c4d529b87fe37a",
        "candidate_prefix": args.candidate_prefix,
        "previous_prefix": args.previous_prefix,
        "behavior_revision": behavior["current_revision"],
        "behavior_surface_sha256": behavior["behavior_surface_sha256"],
        "reference_sha256": {
            name: hashlib.sha256((repository / name).read_bytes()).hexdigest()
            for name in references
        },
        "comparison_policy": "Raw evidence and ground-truth file sets/bytes; established diagnostic and field-level provenance exceptions only. Manifest-listed actual hashes verified.",
        "comparisons": comparisons,
        "resumes": resumes,
        "structure": structural_inventory(repository),
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"PASS: {len(comparisons)} byte comparisons; {len(resumes)} checkpoint resumes")


if __name__ == "__main__":
    main()
