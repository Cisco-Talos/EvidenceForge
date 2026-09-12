"""Compare original-build checkpoints with original uninterrupted evidence."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from compare_cleanup_output import snapshot


def compare_resumed(control: Path, resumed: Path) -> None:
    """Require exact evidence and only the declared resume bookkeeping differences."""
    left, right = snapshot(control), snapshot(resumed)
    del left["GENERATION_MANIFEST.json"], right["GENERATION_MANIFEST.json"]
    if left != right or not left:
        raise ValueError("Resumed evidence differs from original uninterrupted output")
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
    if provenance["migration_count"] != 1 or provenance["omitted_transition_count"] != 0:
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
        "accepted_policy": "compatible",
        "behavior_change": "localized",
        "classification": "load-compatible",
        "confirmation_status": "not-required",
        "runtime_differences": {},
        "from_fingerprint": provenance["origin_fingerprint"],
        "to_fingerprint": provenance["current_fingerprint"],
        "originating_build": provenance["origin_build"],
        "resuming_build": provenance["current_build"],
    }
    if any(transition[key] != value for key, value in expected.items()):
        raise ValueError("Migration drifted from compatible behavior-preserving policy")
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
    args = parser.parse_args()
    shutil.copytree(args.checkpoint, args.output)
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(args.source.resolve() / "src")
    # Resolve macOS /var aliases before protected scratch ancestry validation.
    environment["TMPDIR"] = str(args.output.parent.resolve())
    commands = (
        ["checkpoint", "verify", str(args.output), "--json"],
        ["generate", "--output", str(args.output), "--resume", "--resume-policy", "compatible"],
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
    compare_resumed(args.control, args.output)
    print("PASS: original-build checkpoint hydrated and resumed to byte-identical evidence")


if __name__ == "__main__":
    main()
