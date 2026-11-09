# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Offline Docker reference verification; fixed findings, no captured values."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
from pathlib import Path
from types import ModuleType


def load(name: str, candidates: tuple[str, ...]) -> ModuleType:
    """Load one reviewed co-located tool without launching its capture entrypoint."""
    root = Path(__file__).resolve().parent
    path = next(root / item for item in candidates if (root / item).is_file())
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError("CODE")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


docker = load("_eforge_docker_capture", ("docker_reference.py", "macos_remote_docker_reference.py"))
reviewer = load("_eforge_process_review", ("process_review.py", "macos_remote_process_review.py"))
support = docker.support
PUBLIC_ROLES = frozenset(
    (
        "BACKEND",
        "VIRTUALIZATION",
        "KRUN",
        "BUILD",
        "SAILOR",
        "SOCKET",
        "CLI",
        "DESKTOP_CLI",
        "DESKTOP",
        "HELPER",
        "GPU",
        "PLUGIN",
        "RENDERER",
        "CRASHPAD",
    )
)


def relationships(rows: list[dict], images: list[dict], root: str, controls: list[dict]) -> dict:
    """Check the generic execution graph and Docker-specific independent controls."""
    if any(image.get("role") not in PUBLIC_ROLES for image in images):
        raise ValueError("IMAGE_ROLE")
    matcher = docker.DockerGraph(images, root)
    result = reviewer.relationships(rows, images, root, matcher=matcher)
    # This experiment has no Code shell-discovery workflow. Its launch proof is
    # the unique marker plus installed image, independently corroborated below.
    result.pop("shell_isolation_control")
    launches = [item for item in controls if item.get("kind") == "launch"]
    ends = [item for item in controls if item.get("kind") == "ended"]
    engines = [item for item in controls if item.get("kind") == "engine"]
    roots = [row for row in rows if matcher.is_main(row)]
    result["shell_isolation_control"] = bool(roots) and all(
        item in roots[0]["event"]["exec"]["env"]
        for item in ("ZDOTDIR=" + root + "/shell", "SHELL=/bin/zsh")
    )
    result["launch_control_matches"] = (
        len(launches) == 1
        and launches[0].get("ok") is True
        and any(
            launches[0].get("pid")
            == support.token_words(row["event"]["exec"]["target"]["audit_token"])[5]
            and docker.process.image_matches(row["event"]["exec"]["target"], images[0])
            for row in rows
            if row.get("event_type") == 9
        )
    )
    result["ordinary_exit_control"] = (
        len(ends) == 1 and ends[0].get("terminated") is True and ends[0].get("forced") is False
    )
    result["linux_guest_engine_control"] = (
        len(engines) == 1
        and engines[0].get("server", {}).get("Os") == "linux"
        and engines[0]["server"].get("Arch") == "arm64"
    )
    counts = dict.fromkeys([image["role"] for image in images] + ["UNKNOWN"], 0)
    wait_kinds = dict.fromkeys(("NORMAL", "SIGNALLED", "OTHER"), 0)
    for row in rows:
        if row["event_type"] == 9:
            target = row["event"]["exec"]["target"]
            label = next(
                (image["role"] for image in images if docker.process.image_matches(target, image)),
                "UNKNOWN",
            )
            counts[label] += 1
        elif row["event_type"] == 15:
            wait = row["event"]["exit"]["stat"]
            kind = (
                "NORMAL" if os.WIFEXITED(wait) else "SIGNALLED" if os.WIFSIGNALED(wait) else "OTHER"
            )
            wait_kinds[kind] += 1
    result["selected_image_exec_counts"] = counts
    result["exit_wait_kinds"] = wait_kinds
    return result


def review(work: Path) -> dict:
    """Authenticate the new private artifacts before examining their records."""
    for directory in (work, work / "code", work / "shell"):
        info = directory.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise ValueError("DIRECTORY")
    for name, limit in (
        ("manifest.json", 65536),
        ("REPORT.json", 65536),
        ("controls.json", 65536),
        ("native.ndjson", support.MAX_RETAINED_BYTES),
    ):
        reviewer.shape.checked_file(work / name, limit)
    manifest = support.decode((work / "manifest.json").read_bytes())
    report = support.decode((work / "REPORT.json").read_bytes())
    if manifest["root"] != str(work) or manifest["report"] != report:
        raise ValueError("PROVENANCE")
    for name, filename in (("native", "native.ndjson"), ("controls", "controls.json")):
        if support.digest(work / filename) != manifest[name + "_sha256"]:
            raise ValueError("PROVENANCE")
    hashes = manifest["provenance"]["code_sha256"]
    if set(hashes) != set(docker.CODE_FILES):
        raise ValueError("CODE")
    for name, expected in hashes.items():
        reviewer.shape.checked_file(work / "code" / name, support.MAX_RETAINED_BYTES)
        if support.digest(work / "code" / name) != expected:
            raise ValueError("CODE")
    if report["error"] != "NONE" or not all(
        report.get(name) is True
        for name in (
            "initial_stopped_control",
            "collector_ready",
            "app_launch_control",
            "engine_ready_control",
            "empty_before_quit",
            "ordinary_quit_request",
            "stopped_control",
            "cleanup",
            "original_running_restored",
            "installed_code_unchanged",
        )
    ):
        raise ValueError("CAPTURE_CONTROL")
    controls = json.loads((work / "controls.json").read_bytes())
    if (
        type(controls) is not list
        or len(controls) > 10
        or any(type(item) is not dict for item in controls)
    ):
        raise ValueError("CONTROLS")
    rows = []
    with (work / "native.ndjson").open("rb") as source:
        for line in source:
            if len(rows) >= support.MAX_RETAINED_RECORDS:
                raise ValueError("RECORD_LIMIT")
            rows.append(support.decode(line))
    result = relationships(rows, manifest["images"], str(work), controls)
    result["stream_complete_control"] = (
        report["stream_sequence_gaps"] == 0 and report["stream_sequence_reordered"] is False
    )
    return result


def main() -> None:
    root = Path(__file__).resolve().parent
    attempts = sorted(root.glob("docker-run-*"))
    runs = []
    earlier_profiles = failed_preconditions = invalid_artifacts = 0
    for work in attempts[:8]:
        try:
            reviewer.shape.checked_file(work / "REPORT.json", 65536)
            report = support.decode((work / "REPORT.json").read_bytes())
            if not (work / "shell").is_dir():
                earlier_profiles += 1
            elif report.get("capture_started") is True and report.get("error") == "NONE":
                runs.append(work)
            else:
                failed_preconditions += 1
        except (OSError, ValueError, TypeError, KeyError):
            invalid_artifacts += 1
    reports = []
    for work in runs[:2]:
        try:
            reports.append(review(work))
        except (OSError, ValueError, TypeError, KeyError, IndexError, RecursionError):
            reports.append(
                {"error": "REFERENCE_CHECK_FAILED", "reference_admission": "NOT_EVALUATED"}
            )
    print(
        json.dumps(
            {
                "schema_version": 1,
                "runs": reports,
                "run_limit_exceeded": len(runs) > 2 or len(attempts) > 8,
                "earlier_profile_attempts": earlier_profiles,
                "failed_preconditions": failed_preconditions,
                "invalid_artifacts": invalid_artifacts,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
