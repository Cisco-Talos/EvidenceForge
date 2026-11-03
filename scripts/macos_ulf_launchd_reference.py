# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Prepare a human-run, nonce-filtered launchd Unified Log diagnostic outside Git.

Preparation is code-only. Setup, capture and offline review are human-only unless
separately authorized. No observed strings, paths, identities or native values
are returned by the fixed report. This diagnostic never qualifies a generator.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.formats.macos_unified_log import UnifiedLogRecord

type Check = Literal["PASS", "FAIL", "INCONCLUSIVE"]
type Error = Literal[
    "NONE", "PLATFORM", "LOCATION", "BUILD", "CONTROL", "COLLECTOR", "LIMIT", "DATA"
]
SAFE_ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}
MAX_BYTES = 4 * 1024 * 1024
MAX_LINE = 128 * 1024
GUARD_LABELS = frozenset(
    {
        "REGISTERED",
        "ACTIVATED",
        "REMOVED",
        "FILES_REMOVED",
        "LOCATION_FAIL",
        "REGISTRATION_FAIL",
        "ACTIVATION_FAIL",
        "REMOVAL_FAIL",
        "FILES_FAIL",
    }
)
MARKER = r"""#include <os/log.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    os_log(OS_LOG_DEFAULT, "EFORGE_ULF_READY %{public}s", argv[1]);
    return 0;
}
"""


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Config(Model):
    nonce: str = Field(pattern="^[a-f0-9]{32}$")
    hashes: dict[str, str]


class MessageCounts(Model):
    spawning: int = Field(default=0, ge=0)
    running: int = Field(default=0, ge=0)
    exited_zero: int = Field(default=0, ge=0)
    other_test_item: int = Field(default=0, ge=0)


class LabelMatches(Model):
    """Locate only the generated label, without exposing either native field."""

    message_only: int = Field(default=0, ge=0)
    category_only: int = Field(default=0, ge=0)
    both: int = Field(default=0, ge=0)


class Report(Model):
    kit_version: Literal[1, 2, 3] = 3
    purpose: Literal["LAUNCHD_UNIFIED_LOG_DIAGNOSTIC"] = "LAUNCHD_UNIFIED_LOG_DIAGNOSTIC"
    reference_review: Literal["REQUIRED"] = "REQUIRED"
    gate_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    collection: Literal["NONCE_LABEL_FILTERED_TEST_JOB_ONLY"] = "NONCE_LABEL_FILTERED_TEST_JOB_ONLY"
    error: Error = "NONE"
    stage: Literal["PREPARED", "SETUP_READY", "COMPLETE", "ERROR"] = "ERROR"
    collector_ready: Check = "INCONCLUSIVE"
    readiness_scope: Literal["OWN_PROCESS_MARKER_ONLY"] = "OWN_PROCESS_MARKER_ONLY"
    job_activated: Check = "INCONCLUSIVE"
    job_removed: Check = "INCONCLUSIVE"
    temporary_files_removed: Check = "INCONCLUSIVE"
    collector_cleanup: Check = "INCONCLUSIVE"
    sudo_credentials: Check = "INCONCLUSIVE"
    job_control: Literal[
        "NOT_EVALUATED",
        "PASS",
        "NO_STATUS",
        "LOCATION_FAIL",
        "REGISTRATION_FAIL",
        "ACTIVATION_FAIL",
        "REMOVAL_FAIL",
        "FILES_FAIL",
        "INCOMPLETE",
    ] = "NOT_EVALUATED"
    retained_rows: int = Field(default=0, ge=0, le=256)
    reference_result: Literal[
        "NOT_EVALUATED", "CONTROL_INCOMPLETE", "NO_MATCHING_ROWS", "RECORDS_REQUIRE_REVIEW"
    ] = "NOT_EVALUATED"
    label_matches: LabelMatches = Field(default_factory=LabelMatches)
    native_shapes: Check = "INCONCLUSIVE"
    launchd_writer: Check = "INCONCLUSIVE"
    root_writer: Check = "INCONCLUSIVE"
    subsystem: Literal["XPC_LAUNCHD", "EMPTY", "OTHER", "MIXED", "NOT_OBSERVED"] = "NOT_OBSERVED"
    sender: Literal["MAIN_IMAGE", "LIBXPC", "OTHER", "MIXED", "NOT_OBSERVED"] = "NOT_OBSERVED"
    static_format: Literal["PUBLIC_C_STRING", "C_STRING", "OTHER", "MIXED", "NOT_OBSERVED"] = (
        "NOT_OBSERVED"
    )
    messages: MessageCounts = Field(default_factory=MessageCounts)


class PrivateError(ValueError):
    def __init__(self, code: Error) -> None:
        super().__init__(code)
        self.code = code


def _root(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    info = resolved.stat()
    if (
        resolved != path.absolute()
        or resolved.parent != Path("/private/tmp")
        or not resolved.name.startswith("eforge-ulf-launchd-kit-")
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise PrivateError("LOCATION")
    return resolved


def _read(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or info.st_mode & 0o077
            or info.st_size > MAX_BYTES
        ):
            raise PrivateError("LOCATION")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise PrivateError("LIMIT")
        return raw
    finally:
        os.close(descriptor)


def _write(path: Path, raw: bytes) -> None:
    with path.open("xb") as stream:
        os.chmod(path, 0o600)
        stream.write(raw)


def prepare(destination: Path | None = None) -> Path:
    """Copy public code only; never run commands or inspect a previous kit."""
    root = Path(
        tempfile.mkdtemp(prefix="eforge-ulf-launchd-kit-", dir=destination or "/private/tmp")
    )
    os.chmod(root, 0o700)
    source = Path(__file__).resolve()
    guard = (
        source.parent.parent
        / "docs/design/macos-workstation-feasibility/launchd-reference/job_guard.c"
    )
    for original, name in ((source, "private_ulf_launchd.py"), (guard, "job_guard.c")):
        shutil.copyfile(original, root / name)
        (root / name).chmod(0o600)
    _write(root / "ready.c", MARKER.encode())
    return root


def _platform() -> None:
    """Require the same qualified target at setup and collection."""
    if os.getuid() == 0 or platform.system() != "Darwin" or platform.machine() != "arm64":
        raise PrivateError("PLATFORM")
    if platform.mac_ver()[0].split(".")[0] != "27":
        raise PrivateError("PLATFORM")


def setup(root: Path) -> Report:
    """Human-only control compilation, without running any compiled program."""
    _platform()
    for source, target in (("job_guard.c", "job-guard"), ("ready.c", "ready-marker")):
        result = subprocess.run(
            [
                "/usr/bin/cc",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wno-unused-parameter",
                str(root / source),
                "-o",
                str(root / target),
            ],
            env=SAFE_ENV,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
        if result.returncode:
            raise PrivateError("BUILD")
        (root / target).chmod(0o700)
    names = ("private_ulf_launchd.py", "job_guard.c", "ready.c", "job-guard", "ready-marker")
    config = Config(
        nonce=uuid.uuid4().hex,
        hashes={name: hashlib.sha256(_read(root / name)).hexdigest() for name in names},
    )
    _write(root / "CONFIG.json", config.model_dump_json().encode())
    return Report(stage="SETUP_READY")


def _config(root: Path) -> Config:
    config = Config.model_validate_json(_read(root / "CONFIG.json"))
    names = {"private_ulf_launchd.py", "job_guard.c", "ready.c", "job-guard", "ready-marker"}
    if set(config.hashes) != names or any(
        hashlib.sha256(_read(root / name)).hexdigest() != digest
        for name, digest in config.hashes.items()
    ):
        raise PrivateError("CONTROL")
    return config


def _label_location(
    row: dict, label: str
) -> Literal["message_only", "category_only", "both"] | None:
    """Authenticate the test item in message text or the structured category."""
    text, category = row.get("eventMessage"), row.get("category")
    in_text = isinstance(text, str) and label in text
    in_category = isinstance(category, str) and label in category
    if in_text and in_category:
        return "both"
    if in_text:
        return "message_only"
    if in_category:
        return "category_only"
    return None


def _predicate(config: Config) -> str:
    """Select the same nonce fields at the OS boundary and at retention."""
    label = "org.evidenceforge.reference.launchd." + config.nonce
    return (
        f'(process == "launchd" AND (eventMessage CONTAINS "{label}" '
        f'OR category CONTAINS "{label}")) '
        f'OR (process == "ready-marker" AND eventMessage == "EFORGE_ULF_READY {config.nonce}")'
    )


def _guard_flags(raw: bytes) -> set[str]:
    """Keep only the compiled guard's literal status vocabulary, never command output."""
    return {label for label in GUARD_LABELS if label.encode("ascii") in raw.splitlines()}


def _guard_status(flags: set[str], *, complete: bool) -> str:
    """A failed control is not evidence that a native source is quiet."""
    for failure in (
        "LOCATION_FAIL",
        "REGISTRATION_FAIL",
        "ACTIVATION_FAIL",
        "REMOVAL_FAIL",
        "FILES_FAIL",
    ):
        if failure in flags:
            return failure
    return "PASS" if complete else "INCOMPLETE" if flags else "NO_STATUS"


def analyze(rows: list[dict], label: str, base: Report) -> Report:
    """Return fixed comparisons only; unknown strings never leave private memory."""
    if len(rows) > 256:
        raise PrivateError("LIMIT")
    locations = [_label_location(row, label) for row in rows]
    if any(location is None for location in locations):
        raise PrivateError("CONTROL")
    base = base.model_copy(
        update={
            "retained_rows": len(rows),
            "reference_result": (
                "CONTROL_INCOMPLETE"
                if base.error != "NONE"
                else "RECORDS_REQUIRE_REVIEW"
                if rows
                else "NO_MATCHING_ROWS"
            ),
            "label_matches": LabelMatches(
                message_only=locations.count("message_only"),
                category_only=locations.count("category_only"),
                both=locations.count("both"),
            ),
        }
    )
    if base.error != "NONE":
        return base
    parsed: list[UnifiedLogRecord] = []
    for row in rows:
        try:
            parsed.append(UnifiedLogRecord.model_validate_json(json.dumps(row)))
        except ValueError:
            return base.model_copy(update={"retained_rows": len(rows), "native_shapes": "FAIL"})
    if not parsed:
        return base
    counts = {"spawning": 0, "running": 0, "exited_zero": 0, "other_test_item": 0}
    for row in parsed:
        text = row.event_message
        key = (
            "spawning"
            if "service state: spawning" in text
            else "running"
            if "service state: running" in text
            else "exited_zero"
            if "exited due to exit(0)" in text
            else "other_test_item"
        )
        counts[key] += 1

    def one(values: set[str]) -> str:
        return next(iter(values)) if len(values) == 1 else "MIXED"

    return Report.model_validate(
        base.model_dump()
        | {
            "retained_rows": len(parsed),
            "native_shapes": "PASS",
            "launchd_writer": "PASS"
            if all(r.process_id == 1 and r.process_image_path == "/sbin/launchd" for r in parsed)
            else "FAIL",
            "root_writer": "PASS" if all(r.user_id == 0 for r in parsed) else "FAIL",
            "subsystem": one(
                {
                    "XPC_LAUNCHD"
                    if r.subsystem == "com.apple.xpc.launchd"
                    else "EMPTY"
                    if not r.subsystem
                    else "OTHER"
                    for r in parsed
                }
            ),
            "sender": one(
                {
                    "MAIN_IMAGE"
                    if r.sender_image_path == "/sbin/launchd"
                    else "LIBXPC"
                    if r.sender_image_path == "/usr/lib/system/libxpc.dylib"
                    else "OTHER"
                    for r in parsed
                }
            ),
            "static_format": one(
                {
                    "PUBLIC_C_STRING"
                    if r.format_string == "%{public}s"
                    else "C_STRING"
                    if r.format_string == "%s"
                    else "OTHER"
                    for r in parsed
                }
            ),
            "messages": counts,
        }
    )


def capture(root: Path) -> Report:
    """Human-only live capture: OS predicate and private retention both require the nonce."""
    _platform()
    config = _config(root)
    if (root / "records.ndjson").exists():
        raise PrivateError("CONTROL")
    label = "org.evidenceforge.reference.launchd." + config.nonce
    predicate = _predicate(config)
    rows: list[dict] = []
    flags: set[str] = set()
    ready = False
    collector: subprocess.Popen | None = None
    job: subprocess.Popen | None = None
    cleanup = True
    job_returncode: int | None = None
    buffers: dict[str, bytes] = {"log": b"", "job": b""}
    total = 0
    try:
        collector = subprocess.Popen(
            [
                "/usr/bin/log",
                "stream",
                "--style",
                "ndjson",
                "--level",
                "debug",
                "--predicate",
                predicate,
            ],
            env=SAFE_ENV,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        with selectors.DefaultSelector() as selector:
            selector.register(collector.stdout, selectors.EVENT_READ, "log")
            start = time.monotonic()
            marker_at = 0.0
            removed_at: float | None = None
            while time.monotonic() - start < 35:
                now = time.monotonic()
                if not ready and now - marker_at > 0.5:
                    subprocess.run(
                        [str(root / "ready-marker"), config.nonce],
                        env=SAFE_ENV,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=2,
                        check=True,
                    )
                    marker_at = now
                if not ready and now - start > 8:
                    raise PrivateError("COLLECTOR")
                if ready and job is None:
                    print(
                        '{"purpose":"LAUNCHD_UNIFIED_LOG_DIAGNOSTIC","stage":"COLLECTOR_READY"}',
                        flush=True,
                    )
                    job = subprocess.Popen(
                        ["/usr/bin/sudo", "-n", str(root / "job-guard"), "run", config.nonce],
                        env=SAFE_ENV,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                    )
                    selector.register(job.stdout, selectors.EVENT_READ, "job")
                if collector.poll() is not None:
                    raise PrivateError("COLLECTOR")
                if job is not None and job.poll() is not None and removed_at is None:
                    removed_at = now
                if removed_at is not None and now - removed_at > 2:
                    break
                for key, _mask in selector.select(timeout=0.1):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > MAX_BYTES:
                        raise PrivateError("LIMIT")
                    kind = key.data
                    buffers[kind] += chunk
                    if len(buffers[kind]) > MAX_LINE:
                        raise PrivateError("LIMIT")
                    while b"\n" in buffers[kind]:
                        line, buffers[kind] = buffers[kind].split(b"\n", 1)
                        if kind == "job":
                            flags.update(_guard_flags(line))
                            continue
                        try:
                            row = json.loads(line)
                        except (ValueError, UnicodeError):
                            continue
                        if not isinstance(row, dict):
                            continue
                        text = row.get("eventMessage")
                        if text == "EFORGE_ULF_READY " + config.nonce:
                            ready = True
                        elif (
                            _label_location(row, label) is not None
                            and row.get("processID") == 1
                            and row.get("processImagePath") == "/sbin/launchd"
                        ):
                            rows.append(row)
                            if len(rows) > 256:
                                raise PrivateError("LIMIT")
    finally:
        if job is not None:
            if job.stdin is not None:
                job.stdin.close()
            try:
                job_returncode = job.wait(timeout=12)
            except subprocess.TimeoutExpired:
                cleanup = False
            if job.stdout is not None:
                job.stdout.close()
        if collector is not None:
            collector.terminate()
            try:
                collector.wait(timeout=3)
            except subprocess.TimeoutExpired:
                collector.kill()
                collector.wait(timeout=3)
                cleanup = False
            if collector.stdout is not None:
                collector.stdout.close()
    control_complete = (
        job_returncode == 0
        and {"REGISTERED", "ACTIVATED", "REMOVED", "FILES_REMOVED"} <= flags
        and not any(flag.endswith("_FAIL") for flag in flags)
    )
    error = "CONTROL" if not control_complete else "COLLECTOR" if not cleanup else "NONE"
    base = Report(
        error=error,
        stage="COMPLETE" if error == "NONE" else "ERROR",
        collector_ready="PASS" if ready else "FAIL",
        job_activated="PASS" if "ACTIVATED" in flags else "FAIL",
        job_removed="PASS" if "REMOVED" in flags else "FAIL",
        temporary_files_removed="PASS" if "FILES_REMOVED" in flags else "FAIL",
        collector_cleanup="PASS" if cleanup else "FAIL",
        job_control=_guard_status(flags, complete=control_complete),
    )
    raw = b"".join((json.dumps(row) + "\n").encode() for row in rows)
    if len(raw) > MAX_BYTES:
        raise PrivateError("LIMIT")
    _write(root / "records.ndjson", raw)
    report = analyze(rows, label, base)
    _write(root / "SHAREABLE-ULF-REPORT.json", report.model_dump_json(indent=2).encode())
    return report


def cleanup(root: Path) -> Report:
    """Human-only exact-label recovery; no collector, query or new job is started."""
    _platform()
    config = _config(root)
    credentials = subprocess.run(
        ["/usr/bin/sudo", "-n", "-v"],
        env=SAFE_ENV,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=5,
        check=False,
    )
    if credentials.returncode:
        return Report(error="CONTROL", sudo_credentials="FAIL", job_control="NO_STATUS")
    result = subprocess.run(
        ["/usr/bin/sudo", "-n", str(root / "job-guard"), "cleanup", config.nonce],
        env=SAFE_ENV,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    labels = _guard_flags(result.stdout)
    success = (
        result.returncode == 0
        and {"REMOVED", "FILES_REMOVED"} <= labels
        and not any(flag.endswith("_FAIL") for flag in labels)
    )
    return Report(
        stage="COMPLETE" if success else "ERROR",
        error="NONE" if success else "CONTROL",
        sudo_credentials="PASS",
        job_removed="PASS" if "REMOVED" in labels else "FAIL",
        temporary_files_removed="PASS" if "FILES_REMOVED" in labels else "FAIL",
        job_control=_guard_status(labels, complete=success),
    )


def main() -> int:
    """Expose preparation separately from human-only native operations."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "setup", "capture", "report", "cleanup"))
    parser.add_argument("--private-run", action="store_true")
    parser.add_argument("--kit-root", type=Path)
    args = parser.parse_args()
    if args.kit_root is not None and args.operation != "cleanup":
        parser.error("--kit-root is limited to exact-label cleanup; capture reuse is forbidden")
    if args.operation == "prepare":
        print(json.dumps({"kit": str(prepare()), "stage": "PREPARED"}))
        return 0
    if not args.private_run:
        parser.error(
            "Native operations require explicit --private-run; preparation starts no collection"
        )
    try:
        root = _root(args.kit_root or Path(__file__).absolute().parent)
        if args.operation == "setup":
            result = setup(root)
        elif args.operation == "capture":
            result = capture(root)
        elif args.operation == "cleanup":
            result = cleanup(root)
        else:
            result = Report.model_validate_json(_read(root / "SHAREABLE-ULF-REPORT.json"))
    except PrivateError as error:
        result = Report(error=error.code)
    except (OSError, ValueError, subprocess.SubprocessError):
        result = Report(error="DATA")
    except KeyboardInterrupt:
        result = Report(error="CONTROL")
    print(result.model_dump_json(indent=2))
    return 0 if result.error == "NONE" else 2


if __name__ == "__main__":
    sys.exit(main())
