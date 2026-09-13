"""Verify preserved-build compatible resumes and exact same-build checkpoint resumes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml
from verify_cleanup_resume import bundle_hashes, checkpoint_identity


def run(arguments: list[str], log: Path, *, environment: dict[str, str] | None = None) -> None:
    """Run one gate with its complete diagnostic output retained outside evidence."""
    with log.open("w") as stream:
        subprocess.run(
            arguments,
            env=environment,
            cwd=log.parent,
            stdout=stream,
            stderr=subprocess.STDOUT,
            check=True,
        )


def main() -> None:
    """Keep originals intact and exercise each resume policy on a fresh copy."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--baseline-source", type=Path, required=True)
    parser.add_argument(
        "--control-source",
        type=Path,
        help="Uninterrupted reference build; defaults to baseline-source. Use the accepted correction for semantic fixes.",
    )
    parser.add_argument("--original-checkpoints", type=Path, required=True)
    parser.add_argument(
        "--intermediate-checkpoints",
        type=Path,
        help="Additional checkpoint controls with build identity read from their manifests",
    )
    parser.add_argument(
        "--preserved-build",
        nargs=3,
        action="append",
        default=[],
        metavar=("LABEL", "SOURCE", "CHECKPOINTS"),
        help="Additional preserved source checkout and checkpoint root; repeat for each build",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    for name in (
        "source",
        "baseline_source",
        "control_source",
        "original_checkpoints",
        "intermediate_checkpoints",
        "output",
    ):
        value = getattr(args, name)
        if value is not None:
            setattr(args, name, value.resolve())
    args.output.mkdir(parents=True, exist_ok=False)
    scripts = Path(__file__).resolve().parent
    fixture = args.baseline_source / "tests/fixtures/scenarios/checkpoint-all-formats.yaml"
    environment = os.environ.copy()
    control_source = args.control_source or args.baseline_source
    environment["PYTHONPATH"] = str(control_source.resolve() / "src")
    environment["TMPDIR"] = str(args.output.resolve())
    builds: list[tuple[str, Path | None, Path]] = [
        ("original", args.baseline_source, args.original_checkpoints)
    ]
    if args.intermediate_checkpoints is not None:
        builds.append(("intermediate", None, args.intermediate_checkpoints))
    builds.extend(
        (label, Path(source).resolve(), Path(checkpoints).resolve())
        for label, source, checkpoints in args.preserved_build
    )
    labels = [label for label, _source, _checkpoints in builds]
    if len(set(labels)) != len(labels) or any(
        not label or Path(label).name != label or label in {".", ".."} for label in labels
    ):
        raise ValueError("Preserved build labels must be unique path components")
    expected_builds: dict[str, dict[str, object]] = {}
    for label, source, _checkpoints in builds:
        if source is None:
            continue
        source_environment = os.environ.copy()
        source_environment["PYTHONPATH"] = str(source.resolve() / "src")
        digest = subprocess.check_output(
            [
                sys.executable,
                "-c",
                "from evidenceforge.generation.checkpoints.fingerprint "
                "import installed_build_digest; print(installed_build_digest())",
            ],
            env=source_environment,
            text=True,
        ).strip()
        behavior = yaml.safe_load(
            (source / "src/evidenceforge/config/generation_behavior.yaml").read_text()
        )
        expected_builds[label] = {
            "evidenceforge_build_sha256": digest,
            "behavior_revision": behavior["current_revision"],
        }
    verifications: list[dict[str, Any]] = []
    preserved_hashes: dict[str, dict[str, str]] = {}
    for target in ("default", "sof-elk", "splunk"):
        for seed in (42, 137):
            name = f"{target}-{seed}"
            control = args.output / f"control-{name}"
            run(
                [
                    sys.executable,
                    "-m",
                    "evidenceforge",
                    "generate",
                    str(fixture),
                    "--output",
                    str(control),
                    "--seed",
                    str(seed),
                    "--target",
                    target,
                    "--checkpoint-hours",
                    "0",
                ],
                args.output / f"control-{name}.log",
                environment=environment,
            )
            for label, _source, checkpoint_root in builds:
                retained = checkpoint_root / name
                identity = checkpoint_identity(retained)
                expected = expected_builds.setdefault(
                    label,
                    {
                        key: identity[key]
                        for key in ("behavior_revision", "evidenceforge_build_sha256")
                    },
                )
                if any(identity[key] != value for key, value in expected.items()):
                    raise ValueError(f"Checkpoint does not identify preserved build {label}/{name}")
                before = bundle_hashes(retained)
                preserved_hashes[f"{label}/{name}"] = before
                destination = args.output / f"compatible-{label}-{name}"
                run(
                    [
                        sys.executable,
                        str(scripts / "verify_cleanup_resume.py"),
                        "--source",
                        str(args.source),
                        "--checkpoint",
                        str(retained),
                        "--control",
                        str(control),
                        "--output",
                        str(destination),
                        "--origin-revision",
                        str(identity["behavior_revision"]),
                    ],
                    args.output / f"compatible-{label}-{name}.log",
                )
                if bundle_hashes(retained) != before:
                    raise ValueError(f"Preserved checkpoint changed: {label}/{name}")
                verifications.append(
                    json.loads(destination.with_suffix(".verification.json").read_text())
                )
                print(
                    f"PASS {label} revision {identity['behavior_revision']} / exact rejection / "
                    f"compatible resume: {name}",
                    flush=True,
                )
            checkpoint = args.output / f"same-build-checkpoint-{name}"
            run(
                [
                    sys.executable,
                    str(scripts / "cleanup_checkpoint_fixture.py"),
                    "--source",
                    str(args.source),
                    "--fixture",
                    str(fixture),
                    "--output",
                    str(checkpoint),
                    "--target",
                    target,
                    "--seed",
                    str(seed),
                ],
                args.output / f"same-build-capture-{name}.log",
            )
            run(
                [
                    sys.executable,
                    str(scripts / "verify_cleanup_resume.py"),
                    "--source",
                    str(args.source),
                    "--checkpoint",
                    str(checkpoint),
                    "--control",
                    str(control),
                    "--output",
                    str(args.output / f"exact-{name}"),
                    "--same-build",
                ],
                args.output / f"exact-{name}.log",
            )
            verifications.append(
                json.loads((args.output / f"exact-{name}.verification.json").read_text())
            )
            print(f"PASS same-build exact resume: {name}", flush=True)
    for label, _source, checkpoint_root in builds:
        for target in ("default", "sof-elk", "splunk"):
            for seed in (42, 137):
                name = f"{target}-{seed}"
                if bundle_hashes(checkpoint_root / name) != preserved_hashes[f"{label}/{name}"]:
                    raise ValueError(f"Original bundle changed by end of matrix: {label}/{name}")
    successes = sum(item["successful_resumes"] for item in verifications)
    rejections = sum(item["exact_policy_rejections"] for item in verifications)
    if successes != 6 * (len(builds) + 1) or rejections != 6 * len(builds):
        raise ValueError("Checkpoint matrix has incomplete acceptance counts")
    report = {
        "successful_resumes": successes,
        "exact_policy_rejections": rejections,
        "preserved_builds": expected_builds,
        "original_bundles_unchanged": True,
        "verifications": verifications,
        "control_fixture_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
    }
    with (args.output / "acceptance.json").open("x") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()
