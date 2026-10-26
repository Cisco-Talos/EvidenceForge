# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Stage a HUMAN-ONLY own-descriptor experiment; agents may prepare, never collect.

No descriptor contents, paths, environment or other processes are inspected.
Native identifiers are compared only in the human-run probe's memory, never exported.
Only setup/record/report run on the human's authority with all agents closed.
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
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

logger = logging.getLogger(__name__)
SOURCES = (
    Path(__file__).resolve().parents[1]
    / "docs/design/macos-workstation-feasibility/ssh-descriptor-reference"
)
SAFE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
SLOTS = ("local", "no_pty", "pty")
type Slot = Literal["local", "no_pty", "pty"]
type Check = Literal["PASS", "FAIL", "INCONCLUSIVE"]
type Kind = Literal["VNODE", "PIPE", "SOCKET", "OTHER", "INCONCLUSIVE"]
type Access = Literal["READ", "WRITE", "READ_WRITE", "INCONCLUSIVE"]
type Relation = Literal["SAME", "DIFFERENT", "INCONCLUSIVE"]
type Code = Literal[
    "NONE",
    "INPUT",
    "LOCATION",
    "PLATFORM",
    "ROOT_USER",
    "BUILD",
    "DATA",
    "DUPLICATE",
    "INTERRUPTED",
    "INTERNAL",
]


class PrivateError(ValueError):
    """Fixed diagnostics never carry an argument, path or native exception text."""

    def __init__(self, code: Code) -> None:
        self.code = code
        super().__init__(code)


class Observation(BaseModel):
    """The C probe exports fixed comparisons only, never raw native values."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    inventory_complete: Check = "INCONCLUSIVE"
    instrument_verified: Check = "INCONCLUSIVE"
    only_standard_descriptors: Check = "INCONCLUSIVE"
    stdio_open: Check = "INCONCLUSIVE"
    stat_type_agreement: Check = "INCONCLUSIVE"
    stdio_close_on_exec_clear: Check = "INCONCLUSIVE"
    stdin_kind: Kind = "INCONCLUSIVE"
    stdout_kind: Kind = "INCONCLUSIVE"
    stderr_kind: Kind = "INCONCLUSIVE"
    stdin_access: Access = "INCONCLUSIVE"
    stdout_access: Access = "INCONCLUSIVE"
    stderr_access: Access = "INCONCLUSIVE"
    tty_streams: Literal["ALL", "NONE", "MIXED", "INCONCLUSIVE"] = "INCONCLUSIVE"
    stdout_stderr_object: Relation = "INCONCLUSIVE"
    stdin_stdout_object: Relation = "INCONCLUSIVE"


class Report(BaseModel):
    """A fixed vocabulary report, including diagnostics and deliberately absent coverage."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    kit_version: Literal[1] = 1
    purpose: Literal["SSH_DESCRIPTOR_DIAGNOSTIC"] = "SSH_DESCRIPTOR_DIAGNOSTIC"
    collection: Literal["OWN_PROCESS_ONLY"] = "OWN_PROCESS_ONLY"
    reference_review: Literal["REQUIRED"] = "REQUIRED"
    gate_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    context: Literal["HUMAN_ATTESTED_LOOPBACK"] = "HUMAN_ATTESTED_LOOPBACK"
    error: Code = "NONE"
    contexts: Literal["INCOMPLETE", "COMPLETE"] = "INCOMPLETE"
    provenance: Check = "INCONCLUSIVE"
    local: Observation = Field(default_factory=Observation)
    no_pty: Observation = Field(default_factory=Observation)
    pty: Observation = Field(default_factory=Observation)
    ssh_server_processes: Literal["NOT_INSPECTED"] = "NOT_INSPECTED"
    endpoint_security_export: Literal["NOT_COLLECTED"] = "NOT_COLLECTED"


class Manifest(BaseModel):
    """Private code provenance; digests never enter the shared report."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    source: str = Field(pattern=r"^[a-f0-9]{64}$")
    helper: str = Field(pattern=r"^[a-f0-9]{64}$")
    binary: str = Field(pattern=r"^[a-f0-9]{64}$")


def _outside_git(path: Path) -> None:
    if any((p / ".git").exists() or (p / ".git").is_symlink() for p in (path, *path.parents)):
        raise PrivateError("LOCATION")


def prepare(destination: Path | None = None) -> Path:
    """AGENT-SAFE: copy code/instructions only, without compiling or connecting."""
    parent = (destination.parent if destination else Path("/private/tmp")).resolve(strict=True)
    _outside_git(parent)
    target = (
        parent / destination.name
        if destination
        else Path(tempfile.mkdtemp(prefix="eforge-ssh-fd-kit-", dir=parent))
    )
    # The human launcher embeds the generated path in a remote shell command.
    if any(
        char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_-."
        for char in str(target)
    ):
        raise PrivateError("LOCATION")
    if destination is not None:
        target.mkdir(mode=0o700)
    for source, name in (
        (Path(__file__).resolve(), "private_ssh_descriptors.py"),
        (SOURCES / "ssh_descriptor_probe.c", "ssh_descriptor_probe.c"),
        (SOURCES / "RUN-LOCAL.sh", "RUN-LOCAL.sh"),
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


def _read(path: Path, limit: int = 8192) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
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
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def _preflight() -> None:
    if os.getuid() == 0 or os.geteuid() != os.getuid():
        raise PrivateError("ROOT_USER")
    if (
        sys.platform != "darwin"
        or platform.machine() != "arm64"
        or platform.mac_ver()[0].split(".")[0] != "27"
    ):
        raise PrivateError("PLATFORM")


def _manifest(root: Path) -> Manifest:
    def digest(name: str) -> str:
        return hashlib.sha256(_read(root / name, 1_048_576)).hexdigest()

    return Manifest(
        source=digest("ssh_descriptor_probe.c"),
        helper=digest("private_ssh_descriptors.py"),
        binary=digest("descriptor-probe"),
    )


def _verify(root: Path) -> None:
    if Manifest.model_validate_json(_read(root / "provenance.json")) != _manifest(root):
        raise PrivateError("DATA")


def setup() -> None:
    """HUMAN ONLY: compile the self-only probe; never start SSH or inspect a service."""
    root = _root()
    _preflight()
    binary = root / "descriptor-probe"
    if any(
        path.exists() or path.is_symlink()
        for path in (binary, root / "provenance.json", root / "private")
    ):
        raise PrivateError("DUPLICATE")
    try:
        subprocess.run(
            [
                "/usr/bin/clang",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fno-modules",
                str(root / "ssh_descriptor_probe.c"),
                "-lproc",
                "-o",
                str(binary),
            ],
            cwd=root,
            env=SAFE_ENV,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PrivateError("BUILD") from error
    binary.chmod(0o700)
    (root / "private").mkdir(mode=0o700)
    _write(root / "provenance.json", _manifest(root).model_dump_json().encode())


def _private(root: Path) -> Path:
    path = root / "private"
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise PrivateError("LOCATION")
    return path


def record(slot: Slot, *, ssh_context: bool = False) -> None:
    """HUMAN ONLY: preserve stdin/out/err across exec and hand off one private report FD.

    No subprocess pipe or stream redirection changes the measured standard FDs.
    The C probe excludes only the exact added report FD, and emits fixed enums.
    """
    root = _root()
    _preflight()
    if slot not in SLOTS or ssh_context != (slot != "local"):
        raise PrivateError("INPUT")
    _verify(root)
    path = _private(root) / f"{slot}.json"
    if path.exists() or path.is_symlink():
        raise PrivateError("DUPLICATE")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.set_inheritable(fd, True)
        # Only the reviewed probe runs. SSH is a separate human-run launcher.
        binary = str(root / "descriptor-probe")
        os.execve(binary, [binary, str(fd)], SAFE_ENV)
    finally:
        os.close(fd)


def report() -> Report:
    """HUMAN ONLY: compare exact fixed-vocabulary files, never scan private contents."""
    root = _root()
    _preflight()
    _verify(root)
    private = _private(root)
    observations: dict[str, Observation] = {}
    for slot in SLOTS:
        path = private / f"{slot}.json"
        if path.exists() or path.is_symlink():
            value = _read(path)
            # Successful probe output must contain every observation field.
            if set(Observation.model_validate_json(value).model_fields_set) != set(
                Observation.model_fields
            ):
                raise PrivateError("DATA")
            observations[slot] = Observation.model_validate_json(value)
    return Report(
        provenance="PASS",
        contexts="COMPLETE" if len(observations) == 3 else "INCOMPLETE",
        **observations,
    )


class QuietParser(argparse.ArgumentParser):
    """Never echo user input or native exceptions."""

    def error(self, _message: str) -> None:
        raise PrivateError("INPUT")


def main(argv: list[str] | None = None) -> int:
    """Run explicit preparation or a human-only collection operation."""
    parser = QuietParser(prog="private-ssh-descriptors", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True, parser_class=QuietParser)
    stage = commands.add_parser("prepare", help="AGENT SAFE: code copying only")
    stage.add_argument("--destination", type=Path)
    for command in ("setup", "record", "report"):
        child = commands.add_parser(command, help="HUMAN ONLY; close agents first")
        child.add_argument("--private-run", action="store_true", required=True)
        if command == "record":
            child.add_argument("slot", choices=SLOTS)
            child.add_argument("--ssh-context", action="store_true")
    try:
        args = parser.parse_args(argv)
        if args.command == "prepare":
            print(prepare(args.destination))
        elif args.command == "setup":
            setup()
            print("KIT_READY")
        elif args.command == "record":
            record(args.slot, ssh_context=args.ssh_context)
        else:
            print(report().model_dump_json(indent=2))
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
    os.write(2, b"SSH_DESCRIPTOR_INTERNAL_ERROR\n")


if __name__ == "__main__":
    sys.excepthook = _private_exception_hook
    raise SystemExit(main())
