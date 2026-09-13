"""Compare checkpoint resumes with the selected accepted uninterrupted evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from compare_cleanup_output import snapshot


def bundle_hashes(root: Path) -> dict[str, str]:
    """Hash the entire checkpoint bundle, including diagnostic and control files."""
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def checkpoint_identity(root: Path) -> dict[str, object]:
    """Read the authenticated current manifest without recovering or mutating the bundle."""
    workspace = root / ".eforge-generation"
    pointer = json.loads((workspace / "CURRENT.json").read_text())
    current = pointer["recoveries"][0]
    sequence = current["sequence"]
    if type(sequence) is not int or sequence < 0:
        raise ValueError("Checkpoint sequence is malformed")
    manifest_bytes = (workspace / "recovery" / f"{sequence:020d}" / "manifest.json").read_bytes()
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    if digest != current["manifest_sha256"]:
        raise ValueError("Checkpoint manifest hash disagrees with its current pointer")
    manifest = json.loads(manifest_bytes)
    components = manifest["metadata"]["fingerprint_components"]
    revision = components["behavior_revision"]
    build = components["evidenceforge_build_sha256"]
    if type(revision) is not int or type(build) is not str:
        raise ValueError("Checkpoint build identity is malformed")
    return {
        "behavior_revision": revision,
        "evidenceforge_build_sha256": build,
        "run_fingerprint": manifest["run_fingerprint"],
        "manifest_sha256": digest,
    }


def compare_resumed(
    control: Path,
    resumed: Path,
    *,
    same_build: bool = False,
    expected_change_ids: list[str] | None = None,
) -> None:
    """Require exact evidence and only the declared resume bookkeeping differences."""
    left, right = snapshot(control), snapshot(resumed)
    del left["GENERATION_MANIFEST.json"], right["GENERATION_MANIFEST.json"]
    if left != right or not left:
        raise ValueError("Resumed evidence differs from the selected uninterrupted control")
    original = json.loads((control / "GENERATION_MANIFEST.json").read_text())
    candidate = json.loads((resumed / "GENERATION_MANIFEST.json").read_text())
    provenance = candidate.pop("resume_provenance")
    expected_keys = {
        "current_build",
        "current_fingerprint",
        "migration_count",
        "omitted_transition_count",
        "origin_build",
        "origin_fingerprint",
        "transitions",
    }
    if set(provenance) != expected_keys:
        raise ValueError("Unexpected resume provenance fields")
    if (
        provenance["migration_count"] != (0 if same_build else 1)
        or provenance["omitted_transition_count"] != 0
    ):
        raise ValueError("Expected exactly one original-to-candidate migration")
    if len(provenance["transitions"]) != 1:
        raise ValueError("Migration must retain its exact transition")
    transition = provenance["transitions"][0]
    if set(transition) != {
        "accepted_policy",
        "behavior_change",
        "behavior_change_ids",
        "classification",
        "confirmation_status",
        "cursor",
        "from_fingerprint",
        "originating_build",
        "resuming_build",
        "runtime_differences",
        "to_fingerprint",
    }:
        raise ValueError("Unexpected transition provenance fields")
    expected = {
        "accepted_policy": "exact" if same_build else "compatible",
        "behavior_change": "exact" if same_build else "localized",
        "classification": "exact" if same_build else "load-compatible",
        "confirmation_status": "not-required",
        "runtime_differences": {},
        "from_fingerprint": provenance["origin_fingerprint"],
        "to_fingerprint": provenance["current_fingerprint"],
        "originating_build": provenance["origin_build"],
        "resuming_build": provenance["current_build"],
    }
    if any(transition[key] != value for key, value in expected.items()):
        raise ValueError("Migration drifted from compatible behavior-preserving policy")
    if expected_change_ids is not None and transition["behavior_change_ids"] != expected_change_ids:
        raise ValueError("Resume behavior history differs from the declared refactors")
    if same_build and provenance["origin_fingerprint"] != provenance["current_fingerprint"]:
        raise ValueError("Exact resume unexpectedly changed its fingerprint")
    if transition["cursor"]["completed_simulated_hours"] != 1:
        raise ValueError("Migration did not preserve the frozen checkpoint cursor")
    for document in (original, candidate):
        del document["created_at"]
        # An omitted resume seed adopts checkpoint authority; effective seed still compares.
        seed = document["overrides"].get("generation_seed")
        if seed not in {None, document["generation_seed"]}:
            raise ValueError("Seed override disagrees with effective generation seed")
        document["overrides"]["generation_seed"] = document["generation_seed"]
    if original != candidate:
        raise ValueError("Unexpected generation manifest change outside resume bookkeeping")


def main() -> None:
    """Verify and resume a disposable checkpoint copy, then compare original evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--same-build", action="store_true")
    parser.add_argument("--origin-revision", type=int)
    args = parser.parse_args()
    origin = checkpoint_identity(args.checkpoint)
    if args.origin_revision is not None and args.origin_revision != origin["behavior_revision"]:
        raise ValueError("Supplied origin revision does not identify the preserved checkpoint")
    original_hashes = bundle_hashes(args.checkpoint)
    shutil.copytree(args.checkpoint, args.output)
    if bundle_hashes(args.output) != original_hashes:
        raise ValueError("Checkpoint copy did not preserve all file bytes")
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(args.source.resolve() / "src")
    # Resolve macOS /var aliases before protected scratch ancestry validation.
    environment["TMPDIR"] = str(args.output.parent.resolve())
    if not args.same_build:
        before = bundle_hashes(args.output)
        rejected = subprocess.run(
            [
                sys.executable,
                "-m",
                "evidenceforge",
                "generate",
                "--output",
                str(args.output),
                "--resume",
                "--resume-policy",
                "exact",
            ],
            cwd=args.output.parent,
            env=environment,
            capture_output=True,
            text=True,
        )
        diagnostic = rejected.stdout + rejected.stderr
        args.output.with_suffix(".exact-rejection.log").write_text(diagnostic)
        if rejected.returncode != 1 or "requires the complete original fingerprint" not in " ".join(
            diagnostic.split()
        ):
            raise ValueError("Exact-build policy did not reject the changed build as expected")
        if bundle_hashes(args.output) != before:
            raise ValueError("Rejected exact-build resume changed the checkpoint bundle")
    commands = (
        ["checkpoint", "verify", str(args.output), "--json"],
        [
            "generate",
            "--output",
            str(args.output),
            "--resume",
            "--resume-policy",
            "exact" if args.same_build else "compatible",
        ],
    )
    for index, arguments in enumerate(commands):
        with args.output.with_suffix(f".step-{index}.log").open("w") as log:
            subprocess.run(
                [sys.executable, "-m", "evidenceforge", *arguments],
                cwd=args.output.parent,
                env=environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=True,
            )
    import yaml

    behavior = yaml.safe_load(
        (args.source / "src/evidenceforge/config/generation_behavior.yaml").read_text()
    )
    expected_changes = (
        []
        if args.same_build
        else [
            change["id"]
            for change in behavior["changes"]
            if change["revision"] > origin["behavior_revision"]
        ]
    )
    compare_resumed(
        args.control, args.output, same_build=args.same_build, expected_change_ids=expected_changes
    )
    if bundle_hashes(args.checkpoint) != original_hashes:
        raise ValueError("Preserved original checkpoint changed during verification")
    report = {
        "origin": origin,
        "same_build": args.same_build,
        "successful_resumes": 1,
        "exact_policy_rejections": 0 if args.same_build else 1,
        "original_bundle_hashes": original_hashes,
        "original_bundle_unchanged": True,
        "rejected_bundle_unchanged": None if args.same_build else True,
        "resumed_evidence_hashes": snapshot(args.output),
    }
    with args.output.with_suffix(".verification.json").open("x") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print("PASS: checkpoint policy, hydration, provenance, and byte-identical resumed evidence")


if __name__ == "__main__":
    main()
