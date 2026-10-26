# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Prepare a private own-process GUI audit probe. Agents must never record or report.

Only prepare/help, syntax-only C compilation and invented-input tests are agent-safe.
No system log reader, process inventory, network, sudo or setting change is used.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

logger = logging.getLogger(__name__)
SOURCES = (
    Path(__file__).resolve().parents[1]
    / "docs/design/macos-workstation-feasibility/gui-audit-reference"
)
SAFE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
MAX_BYTES = 8192
SLOTS = ("window_a", "window_b", "tab", "fresh_login")
type Slot = Literal["window_a", "window_b", "tab", "fresh_login"]
type Check = Literal["PASS", "FAIL", "INCONCLUSIVE"]
type Relation = Literal["SAME", "DIFFERENT", "MIXED", "INCONCLUSIVE"]
type Code = Literal[
    "NONE",
    "INPUT",
    "LOCATION",
    "PLATFORM",
    "ROOT_USER",
    "BUILD",
    "PROBE",
    "DATA",
    "DUPLICATE",
    "INTERRUPTED",
    "INTERNAL",
]
type UInt32 = Annotated[int, Field(strict=True, ge=0, lt=2**32)]
type PositiveID = Annotated[int, Field(strict=True, gt=0, lt=2**31)]


class PrivateError(ValueError):
    """A fixed code; never attach a native value, path or exception message."""

    def __init__(self, code: Code) -> None:
        self.code = code
        super().__init__(code)


class Snapshot(BaseModel):
    """Private selected own-process fields, never a log record or a public DTO."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    pid: PositiveID
    ppid: PositiveID
    sid: PositiveID
    pgid: PositiveID
    uid: UInt32
    euid: UInt32
    gid: UInt32
    egid: UInt32
    auid: UInt32
    asid: UInt32
    token_pid: UInt32
    token_uid: UInt32
    token_euid: UInt32
    token_gid: UInt32
    token_egid: UInt32


class Probe(BaseModel):
    """Only three snapshots of this controlled process family."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    root: Snapshot
    forked: Snapshot
    executed: Snapshot


class Sample(BaseModel):
    """Private per-context input. Raw IDs/digests never enter the report model."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    kit_version: Literal[1] = 1
    slot: Slot
    shell_pid: PositiveID
    os_major: Literal[27] = 27
    architecture: Literal["arm64"] = "arm64"
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    helper_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    binary_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    same_boot_gui_relogin_attested: bool = False
    probe: Probe


class Report(BaseModel):
    """Entire shareable vocabulary: literals and fixed checks, no native values."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    kit_version: Literal[1] = 1
    purpose: Literal["GUI_AUDIT_IDENTITY_DIAGNOSTIC"] = "GUI_AUDIT_IDENTITY_DIAGNOSTIC"
    collection: Literal["OWN_PROCESS_ONLY"] = "OWN_PROCESS_ONLY"
    reference_review: Literal["REQUIRED"] = "REQUIRED"
    gate_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    error: Code = "NONE"
    terminal_contexts: Literal["INCOMPLETE", "COMPLETE"] = "INCOMPLETE"
    provenance_agreement: Check = "INCONCLUSIVE"
    own_token_agreement: Check = "INCONCLUSIVE"
    attributed_audit_identity: Check = "INCONCLUSIVE"
    audit_user_matches_real_user: Check = "INCONCLUSIVE"
    fork_linkage: Check = "INCONCLUSIVE"
    fork_preserves_audit_identity: Check = "INCONCLUSIVE"
    exec_preserves_audit_identity: Check = "INCONCLUSIVE"
    fork_exec_preserve_posix_session: Check = "INCONCLUSIVE"
    distinct_terminal_shells: Check = "INCONCLUSIVE"
    same_real_user: Check = "INCONCLUSIVE"
    terminal_audit_user: Relation = "INCONCLUSIVE"
    terminal_audit_session: Relation = "INCONCLUSIVE"
    terminal_posix_session: Relation = "INCONCLUSIVE"
    fresh_gui_login_audit_session: Relation = "INCONCLUSIVE"
    fresh_gui_login_audit_user: Relation = "INCONCLUSIVE"
    fresh_login_context: Literal["NOT_COLLECTED", "HUMAN_ATTESTED_SAME_BOOT"] = "NOT_COLLECTED"
    gui_startup_log_layout: Literal["NOT_COLLECTED"] = "NOT_COLLECTED"
    endpoint_security_export: Literal["NOT_COLLECTED"] = "NOT_COLLECTED"


def _check(condition: bool) -> Check:
    return "PASS" if condition else "FAIL"


def _relation(values: list[int]) -> Relation:
    if len(values) < 2:
        return "INCONCLUSIVE"
    return (
        "SAME"
        if len(set(values)) == 1
        else "DIFFERENT"
        if len(set(values)) == len(values)
        else "MIXED"
    )


def analyze(samples: tuple[Sample, ...]) -> Report:
    """Compare private facts without exporting their contents or assuming a native outcome."""
    if not samples:
        return Report()
    if any(type(item) is not Sample for item in samples):
        raise PrivateError("DATA")
    slots = {item.slot: item for item in samples}
    if len(slots) != len(samples) or any(
        (s.slot == "fresh_login") != s.same_boot_gui_relogin_attested for s in samples
    ):
        raise PrivateError("DATA")
    provenance = len({(s.source_sha256, s.helper_sha256, s.binary_sha256) for s in samples}) == 1
    snapshots = [view for s in samples for view in (s.probe.root, s.probe.forked, s.probe.executed)]
    token_ok = all(
        (s.pid, s.uid, s.euid, s.gid, s.egid)
        == (s.token_pid, s.token_uid, s.token_euid, s.token_gid, s.token_egid)
        for s in snapshots
    )
    attributed = all(s.auid != 2**32 - 1 and s.asid not in {0, 2**32 - 1} for s in snapshots)
    linkage = all(
        s.probe.root.pid != s.probe.forked.pid
        and s.probe.forked.pid == s.probe.executed.pid
        and s.probe.forked.ppid == s.probe.executed.ppid == s.probe.root.pid
        for s in samples
    )
    terminal = [slots[key] for key in SLOTS[:3] if key in slots]
    complete = len(terminal) == 3
    same_user = len({s.uid for s in snapshots}) == 1
    distinct_shells = len({s.shell_pid for s in terminal}) == 3
    ready = (
        complete
        and provenance
        and token_ok
        and attributed
        and linkage
        and same_user
        and distinct_shells
    )
    report = Report(
        terminal_contexts="COMPLETE" if complete else "INCOMPLETE",
        provenance_agreement=_check(provenance),
        own_token_agreement=_check(token_ok),
        attributed_audit_identity=_check(attributed),
        audit_user_matches_real_user=_check(all(s.auid == s.uid for s in snapshots)),
        fork_linkage=_check(linkage),
        fork_preserves_audit_identity=_check(
            all(
                (s.probe.root.auid, s.probe.root.asid) == (s.probe.forked.auid, s.probe.forked.asid)
                for s in samples
            )
        ),
        exec_preserves_audit_identity=_check(
            all(
                (s.probe.forked.auid, s.probe.forked.asid)
                == (s.probe.executed.auid, s.probe.executed.asid)
                for s in samples
            )
        ),
        fork_exec_preserve_posix_session=_check(
            all(
                (s.probe.root.sid, s.probe.root.pgid)
                == (s.probe.forked.sid, s.probe.forked.pgid)
                == (s.probe.executed.sid, s.probe.executed.pgid)
                for s in samples
            )
        ),
        distinct_terminal_shells=_check(distinct_shells) if complete else "INCONCLUSIVE",
        same_real_user=_check(same_user),
        terminal_audit_user=_relation([s.probe.root.auid for s in terminal])
        if ready
        else "INCONCLUSIVE",
        terminal_audit_session=_relation([s.probe.root.asid for s in terminal])
        if ready
        else "INCONCLUSIVE",
        terminal_posix_session=_relation([s.probe.root.sid for s in terminal])
        if ready
        else "INCONCLUSIVE",
    )
    fresh = slots.get("fresh_login")
    if fresh is not None:
        report = report.model_copy(update={"fresh_login_context": "HUMAN_ATTESTED_SAME_BOOT"})
    if (
        fresh is not None
        and ready
        and report.terminal_audit_session == "SAME"
        and report.terminal_audit_user == "SAME"
    ):
        report = report.model_copy(
            update={
                "fresh_gui_login_audit_session": _relation(
                    [terminal[0].probe.root.asid, fresh.probe.root.asid]
                ),
                "fresh_gui_login_audit_user": _relation(
                    [terminal[0].probe.root.auid, fresh.probe.root.auid]
                ),
            }
        )
    return report


def _outside_git(path: Path) -> None:
    if any((p / ".git").exists() or (p / ".git").is_symlink() for p in (path, *path.parents)):
        raise PrivateError("LOCATION")


def prepare(destination: Path | None = None) -> Path:
    """Copy code/instructions only. Never compile, probe, inspect samples or collect."""
    parent = (destination.parent if destination else Path("/private/tmp")).resolve(strict=True)
    _outside_git(parent)
    target = (
        parent / destination.name
        if destination
        else Path(tempfile.mkdtemp(prefix="eforge-gui-audit-kit-", dir=parent))
    )
    if destination is not None:
        target.mkdir(mode=0o700)
    for source, name in (
        (Path(__file__).resolve(), "private_gui_audit.py"),
        (SOURCES / "gui_audit_probe.c", "gui_audit_probe.c"),
        (SOURCES / "PRIVATE-RUN.md", "PRIVATE-RUN.md"),
    ):
        shutil.copyfile(source, target / name)
        (target / name).chmod(0o600)
    return target


def _root() -> Path:
    root = Path(__file__).resolve().parent
    _outside_git(root)
    info = root.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise PrivateError("LOCATION")
    return root


def _read(path: Path, limit: int = MAX_BYTES) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or info.st_mode & 0o077
        ):
            raise PrivateError("LOCATION")
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise PrivateError("DATA")
        return data


def _write(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


def _digest(path: Path) -> str:
    return hashlib.sha256(_read(path, 1_048_576)).hexdigest()


def _preflight() -> None:
    if os.getuid() == 0 or os.geteuid() != os.getuid():
        raise PrivateError("ROOT_USER")
    if (
        sys.platform != "darwin"
        or platform.machine() != "arm64"
        or platform.mac_ver()[0].split(".")[0] != "27"
    ):
        raise PrivateError("PLATFORM")


def _command(args: list[str], root: Path, code: Code, timeout: int) -> bytes:
    try:
        result = subprocess.run(
            args,
            cwd=root,
            env=SAFE_ENV,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PrivateError(code) from error
    if len(result.stdout) > MAX_BYTES:
        raise PrivateError("DATA")
    return result.stdout


def record(slot: Slot, *, same_boot_gui_relogin: bool = False) -> None:
    """HUMAN ONLY: sample this own-process family in a manually selected GUI context."""
    root = _root()
    _preflight()
    if slot not in SLOTS or (slot == "fresh_login") != same_boot_gui_relogin:
        raise PrivateError("INPUT")
    private = root / "private"
    if not private.exists():
        if slot != "window_a":
            raise PrivateError("INPUT")
        private.mkdir(mode=0o700)
    if (
        private.is_symlink()
        or private.stat().st_uid != os.getuid()
        or private.stat().st_mode & 0o077
    ):
        raise PrivateError("LOCATION")
    destination = private / f"{slot}.json"
    if destination.exists() or destination.is_symlink():
        raise PrivateError("DUPLICATE")
    binary = root / "audit-probe"
    helper_hash = _digest(root / "private_gui_audit.py")
    source_hash = _digest(root / "gui_audit_probe.c")
    if slot == "window_a":
        if binary.exists() or binary.is_symlink():
            raise PrivateError("DUPLICATE")
        _command(
            [
                "/usr/bin/clang",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fno-modules",
                str(root / "gui_audit_probe.c"),
                "-lbsm",
                "-o",
                str(binary),
            ],
            root,
            "BUILD",
            30,
        )
        binary.chmod(0o700)
    else:
        first = Sample.model_validate_json(_read(private / "window_a.json"))
        if (first.source_sha256, first.helper_sha256, first.binary_sha256) != (
            source_hash,
            helper_hash,
            _digest(binary),
        ):
            raise PrivateError("DATA")
    binary_hash = _digest(binary)
    probe = Probe.model_validate_json(_command([str(binary)], root, "PROBE", 12))
    sample = Sample(
        slot=slot,
        shell_pid=os.getppid(),
        source_sha256=source_hash,
        helper_sha256=helper_hash,
        binary_sha256=binary_hash,
        same_boot_gui_relogin_attested=same_boot_gui_relogin,
        probe=probe,
    )
    _write(destination, sample.model_dump_json().encode() + b"\n")


def report() -> Report:
    """HUMAN ONLY: read exact private sample files and return fixed comparisons."""
    root = _root()
    _preflight()
    private = root / "private"
    if (
        private.is_symlink()
        or not private.is_dir()
        or private.stat().st_uid != os.getuid()
        or private.stat().st_mode & 0o077
    ):
        raise PrivateError("LOCATION")
    samples: list[Sample] = []
    for slot in SLOTS:
        path = private / f"{slot}.json"
        if path.exists() or path.is_symlink():
            sample = Sample.model_validate_json(_read(path))
            if sample.slot != slot:
                raise PrivateError("DATA")
            samples.append(sample)
    return analyze(tuple(samples))


class QuietParser(argparse.ArgumentParser):
    """Never echo a user argument, private path or raw exception in diagnostics."""

    def error(self, _message: str) -> None:
        raise PrivateError("INPUT")


def main(argv: list[str] | None = None) -> int:
    """Dispatch code preparation or explicitly human-run own-process checks."""
    parser = QuietParser(prog="private-gui-audit", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True, parser_class=QuietParser)
    stage = commands.add_parser("prepare", help="Agent-safe code copying only")
    stage.add_argument("--destination", type=Path)
    capture = commands.add_parser("record", help="HUMAN ONLY; close agents first")
    capture.add_argument("slot", choices=SLOTS)
    capture.add_argument("--private-run", action="store_true", required=True)
    capture.add_argument("--same-boot-gui-relogin", action="store_true")
    review = commands.add_parser("report", help="HUMAN ONLY; fixed comparisons, no raw IDs")
    review.add_argument("--private-run", action="store_true", required=True)
    try:
        args = parser.parse_args(argv)
        if args.command == "prepare":
            print(prepare(args.destination))
            return 0
        if args.command == "record":
            record(args.slot, same_boot_gui_relogin=args.same_boot_gui_relogin)
            print("SAMPLE_SAVED_PRIVATELY")
            return 0
        result = report()
        print(result.model_dump_json(indent=2))
        return 0
    except PrivateError as error:
        result = Report(error=error.code)
    except KeyboardInterrupt:
        result = Report(error="INTERRUPTED")
    except ValidationError:
        result = Report(error="DATA")
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        result = Report(error="INTERNAL")
    print(result.model_dump_json(indent=2))
    return 2


def _private_exception_hook(_kind: object, _value: object, _traceback: object) -> None:
    os.write(2, b"GUI_AUDIT_INTERNAL_ERROR\n")


if __name__ == "__main__":
    sys.excepthook = _private_exception_hook
    raise SystemExit(main())
