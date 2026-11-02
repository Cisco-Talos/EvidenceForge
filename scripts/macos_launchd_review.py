# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Prepare a fixed-output, read-only review of an existing launchd reference.

Preparation never opens a handed-off kit. Review requires separate permission
and never starts commands, probes, jobs, collectors or live identity queries.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path
from types import ModuleType
from typing import Literal

from pydantic import Field


def _load_capture() -> ModuleType:
    path = Path(__file__).resolve().with_name("private_launchd.py")
    if not path.exists():
        path = Path(__file__).resolve().with_name("macos_launchd_reference.py")
    name = "_eforge_offline_launchd_support"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("BUILD")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


capture = _load_capture()
reference = capture.reference
type Check = Literal["PASS", "FAIL", "INCONCLUSIVE"]
type Key = Literal[
    "PATH",
    "LANG",
    "LC_ALL",
    "CONTROL_TOKEN",
    "XPC_FLAGS",
    "XPC_SERVICE_NAME",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TMPDIR",
    "CF_TEXT_ENCODING",
    "OS_ACTIVITY_DT_MODE",
    "COMMAND_MODE",
    "MALLOC_NANO_ZONE",
    "OS_LOG_RATE_LIMIT",
]
type ValueClass = Literal[
    "CONTROLLED",
    "TEST_LABEL",
    "HEX_ZERO",
    "DECIMAL_ZERO",
    "HEX_ONE",
    "DECIMAL_ONE",
    "ROOT_HOME",
    "ROOT_ACCOUNT",
    "SYSTEM_SH",
    "SYSTEM_ZSH",
    "ROOT_TEMP_DIRECTORY",
    "SYSTEM_PATH",
    "ROOT_ENCODING",
    "UNIX2003",
    "DECIMAL_SIXTY_FOUR",
    "OTHER",
]
KEYS: dict[str, Key] = {
    "PATH": "PATH",
    "LANG": "LANG",
    "LC_ALL": "LC_ALL",
    "EFORGE_LAUNCHD_REFERENCE_TOKEN": "CONTROL_TOKEN",
    "XPC_FLAGS": "XPC_FLAGS",
    "XPC_SERVICE_NAME": "XPC_SERVICE_NAME",
    "HOME": "HOME",
    "USER": "USER",
    "LOGNAME": "LOGNAME",
    "SHELL": "SHELL",
    "TMPDIR": "TMPDIR",
    "__CF_USER_TEXT_ENCODING": "CF_TEXT_ENCODING",
    "OS_ACTIVITY_DT_MODE": "OS_ACTIVITY_DT_MODE",
    "COMMAND_MODE": "COMMAND_MODE",
    "MallocNanoZone": "MALLOC_NANO_ZONE",
    "OSLogRateLimit": "OS_LOG_RATE_LIMIT",
}


class Entry(reference.Model):
    """An allowlisted public key class and fixed comparison, never observed text."""

    key: Key
    value: ValueClass


class Environment(reference.Model):
    vectors_well_formed: Check = "INCONCLUSIVE"
    duplicate_keys: Literal["ABSENT", "PRESENT", "INCONCLUSIVE"] = "INCONCLUSIVE"
    only_known_keys: Check = "INCONCLUSIVE"
    entries: tuple[Entry, ...] = Field(default=(), max_length=16)


class Report(reference.Model):
    review_version: Literal[1, 2] = 2
    purpose: Literal["LAUNCHD_ENVIRONMENT_OFFLINE_REVIEW"] = "LAUNCHD_ENVIRONMENT_OFFLINE_REVIEW"
    mode: Literal["OFFLINE_ONLY"] = "OFFLINE_ONLY"
    reference_review: Literal["REQUIRED"] = "REQUIRED"
    gate_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    error: capture.Error = "NONE"
    provenance: Check = "INCONCLUSIVE"
    original_collection_controls: Check = "INCONCLUSIVE"
    exact_retained_graph: Check = "INCONCLUSIVE"
    launcher: Environment = Field(default_factory=Environment)
    target: Environment = Field(default_factory=Environment)
    environment_vectors_identical: Check = "INCONCLUSIVE"
    collectors: Literal["NOT_STARTED"] = "NOT_STARTED"
    commands: Literal["NOT_STARTED"] = "NOT_STARTED"
    live_queries: Literal["NOT_PERFORMED"] = "NOT_PERFORMED"
    writes: Literal["NONE"] = "NONE"


def _model(path: Path, model: type) -> object:
    raw = reference._read(path)
    reference._decode(raw)
    return model.model_validate_json(raw)


def _verified(root: Path, expected: dict[str, str]) -> tuple[object, list[dict]]:
    reference._outside_git(root)
    reference._directory(root)
    manifest = _model(root / "SETUP.json", capture.Manifest)
    run = reference._active(root)
    provenance = _model(run / "provenance.json", capture.Manifest)
    report = _model(run / "SHAREABLE-REPORT.json", capture.Report)
    if (
        manifest != provenance
        or set(expected) != set(capture.CODE)
        or manifest.code_sha256 != expected
        or any(reference._digest(root / name) != digest for name, digest in expected.items())
        or manifest.guard_sha256 != reference._digest(root / "collector-guard")
        or manifest.job_guard_sha256 != reference._digest(root / "job-guard")
        or manifest.ready_marker.sha256 != reference._digest(root / "ready-marker")
        or manifest.codec_sha256 != reference._codec_digest()
        or set(manifest.images) != set(capture.PATHS)
    ):
        raise reference.PrivateError("BUILD")
    if (
        report.error != "NONE"
        or report.stage != "COMPLETE"
        or report.wire_profile != "V11"
        or report.candidate_ring_evicted
        or report.limit_scope != "NOT_REACHED"
        or any(
            getattr(report, key) != "PASS"
            for key in (
                "provenance",
                "target_platform",
                "collector_ready",
                "collector_cleanup",
                "job_guard",
                "job_registered",
                "job_activated",
                "job_removed",
                "temporary_files_removed",
                "bounded_collection",
                "sequence_continuity",
                "target_control",
                "root_lineage",
                "target_exit_zero",
            )
        )
    ):
        raise reference.PrivateError("DATA")
    lines = reference._read(
        run / "launchd-chain-events.jsonl", 32 * reference.MAX_LINE
    ).splitlines()
    if not 1 <= len(lines) <= capture.MAX_RETAINED or any(
        not line or len(line) > reference.MAX_LINE for line in lines
    ):
        raise reference.PrivateError("LIMIT")
    rows = [reference._decode(line) for line in lines]
    for line in lines:
        reference.decode_endpoint_security_record(line.decode())
    samples = [
        i
        for i, row in enumerate(rows)
        if row["event_type"] == 9 and capture._controlled(row["event"]["exec"], manifest)
    ]
    if len(samples) != 1 or capture.select(rows, samples[0], manifest) != list(range(len(rows))):
        raise reference.PrivateError("DATA")
    phases, graph = capture.analyze(lines, manifest, root)
    if phases != report.phases or graph != report.graph:
        raise reference.PrivateError("DATA")
    return manifest, rows


def classify(payload: dict, manifest: object) -> Environment:
    """Classify only predeclared public keys; unknown keys/values never leave memory."""
    pairs = [
        entry.decode().split("=", 1) for entry in capture.shared._environment(payload.get("env"))
    ]
    if any(len(pair) != 2 or not pair[0] for pair in pairs):
        raise reference.PrivateError("DATA")
    items = dict(pairs)
    controls = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "EFORGE_LAUNCHD_REFERENCE_TOKEN": manifest.nonce,
    }
    entries = []
    for key, value in items.items():
        if key not in KEYS:
            continue
        classified: ValueClass = "OTHER"
        if key in controls and value == controls[key]:
            classified = "CONTROLLED"
        elif key == "XPC_SERVICE_NAME" and value == capture._label(manifest):
            classified = "TEST_LABEL"
        elif key in {"XPC_FLAGS", "OS_ACTIVITY_DT_MODE", "MallocNanoZone"}:
            classified = {
                "0": "DECIMAL_ZERO",
                "1": "DECIMAL_ONE",
                "0x0": "HEX_ZERO",
                "0x1": "HEX_ONE",
            }.get(value, "OTHER")
        elif key == "HOME" and value == "/var/root":
            classified = "ROOT_HOME"
        elif key in {"USER", "LOGNAME"} and value == "root":
            classified = "ROOT_ACCOUNT"
        elif key == "SHELL":
            classified = {"/bin/sh": "SYSTEM_SH", "/bin/zsh": "SYSTEM_ZSH"}.get(value, "OTHER")
        elif (
            key == "TMPDIR"
            and (
                value.startswith("/var/folders/zz/") or value.startswith("/private/var/folders/zz/")
            )
            and value.endswith("/T/")
        ):
            classified = "ROOT_TEMP_DIRECTORY"
        elif key == "PATH" and value == "/usr/bin:/bin:/usr/sbin:/sbin":
            classified = "SYSTEM_PATH"
        elif key == "__CF_USER_TEXT_ENCODING" and value == "0x0:0:0":
            classified = "ROOT_ENCODING"
        elif key == "COMMAND_MODE" and value == "unix2003":
            classified = "UNIX2003"
        elif key == "OSLogRateLimit" and value == "64":
            classified = "DECIMAL_SIXTY_FOUR"
        entries.append(Entry(key=KEYS[key], value=classified))
    return Environment(
        vectors_well_formed="PASS",
        duplicate_keys="ABSENT" if len(items) == len(pairs) else "PRESENT",
        only_known_keys=reference._check(set(items) <= set(KEYS)),
        entries=tuple(sorted(entries, key=lambda entry: entry.key)),
    )


def review_existing(root: Path, expected: dict[str, str]) -> Report:
    """AUTHORIZED READ ONLY: reuse the existing bounded native file, returning fixed classes."""
    manifest, rows = _verified(root, expected)
    execs = [row["event"]["exec"] for row in rows if row["event_type"] == 9]
    if len(execs) != 2 or [capture._public_role(item["target"], manifest) for item in execs] != [
        "XPCPROXY",
        "TARGET",
    ]:
        raise reference.PrivateError("DATA")
    return Report(
        provenance="PASS",
        original_collection_controls="PASS",
        exact_retained_graph="PASS",
        launcher=classify(execs[0], manifest),
        target=classify(execs[1], manifest),
        environment_vectors_identical=reference._check(execs[0]["env"] == execs[1]["env"]),
    )


def prepare(destination: Path | None = None) -> Path:
    """AGENT SAFE: prepare code/expected digests without opening a prior kit."""
    root = capture.prepare(destination)
    shutil.copyfile(Path(__file__).resolve(), root / "private_launchd_review.py")
    (root / "private_launchd_review.py").chmod(0o600)
    expected = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in capture.CODE
    }
    reference._write(root / "OFFLINE-EXPECTED.json", json.dumps(expected).encode())
    return root


def main() -> None:
    """Keep every malformed input/native failure inside the closed report schema."""
    try:
        parser = reference.QuietParser(description=__doc__)
        parser.add_argument("operation", choices=("prepare", "review-existing"))
        parser.add_argument("--private-run", action="store_true")
        parser.add_argument("--source-kit", type=Path)
        args = parser.parse_args()
        if args.operation == "prepare":
            if args.private_run or args.source_kit is not None:
                raise reference.PrivateError("INPUT")
            print(prepare())
            return
        if not args.private_run or args.source_kit is None:
            raise reference.PrivateError("INPUT")
        own_root = Path(__file__).resolve().parent
        reference._outside_git(own_root)
        reference._directory(own_root)
        expected = reference._decode(reference._read(own_root / "OFFLINE-EXPECTED.json"))
        report = review_existing(args.source_kit, expected)
    except (
        reference.PrivateError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        AttributeError,
        RecursionError,
    ) as error:
        report = Report(error=capture._failure(error))
    print(report.model_dump_json(indent=2), flush=True)


if __name__ == "__main__":
    sys.excepthook = lambda _kind, _value, _traceback: print(
        Report(error="INTERNAL").model_dump_json()
    )
    main()
