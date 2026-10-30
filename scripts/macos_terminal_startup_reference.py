# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Prepare a human-only terminal startup reference; agents must not run collection.

The isolated kit reuses the reviewed fixed-output GUI reference helpers by an
explicit sibling-file import. It never searches cwd or modifies sys.path.
Only prepare and invented-input tests are appropriate in an agent session.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from collections import deque
from pathlib import Path
from types import ModuleType
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError


def _load_support() -> ModuleType:
    """Load the exact bundled helper, including when Python runs with -I."""
    path = Path(__file__).resolve().with_name("reference_support.py")
    if not path.exists():
        path = Path(__file__).resolve().with_name("macos_gui_launch_reference.py")
    name = "_eforge_terminal_reference_support"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("REFERENCE_SUPPORT")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


reference = _load_support()
type Check = Literal["PASS", "FAIL", "INCONCLUSIVE"]
type Terminal = Literal["apple", "iterm2"]
type Role = Literal[
    "LAUNCHD", "XPCPROXY", "APPLE_TERMINAL", "ITERM2", "LOGIN", "ZSH", "BASH", "MARKER", "OTHER"
]
PATHS: dict[Terminal, str] = {
    "apple": "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
    "iterm2": "/Applications/iTerm.app/Contents/MacOS/iTerm2",
}
ROLES: dict[str, Role] = {
    "/sbin/launchd": "LAUNCHD",
    "/usr/libexec/xpcproxy": "XPCPROXY",
    PATHS["apple"]: "APPLE_TERMINAL",
    PATHS["iterm2"]: "ITERM2",
    "/usr/bin/login": "LOGIN",
    "/bin/zsh": "ZSH",
    "/bin/bash": "BASH",
}
CODE = (
    "private_terminal_startup.py",
    "reference_support.py",
    "terminal_marker.c",
    "collector_guard.c",
)
MAX_RING_BYTES = 8 * 1_048_576
MAX_RING_ROWS = 512
MAX_CHAIN_ROWS = 48


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Manifest(Model):
    terminal: Terminal
    os_version: str = Field(pattern=r"^27(?:\.[0-9]+){0,2}$")
    os_build: str = Field(pattern=r"^[0-9A-Za-z]+$")
    app: reference.Image
    marker: reference.Image
    guard_sha256: str = Field(pattern="^[a-f0-9]{64}$")
    codec_sha256: str = Field(pattern="^[a-f0-9]{64}$")
    code_sha256: dict[str, str]
    own_uid: int = Field(ge=1, lt=2**32 - 1)
    own_gid: int = Field(ge=0, lt=2**32)
    own_username: str = Field(min_length=1, max_length=1024)
    own_home: str = Field(min_length=1, max_length=4096)


class Phase(Model):
    role: Role
    before_role: Role
    same_pid_replacement: Check
    native_shape: Check
    shape_excluding_entitlements: Check
    fork_linkage: Check
    audit_origin_preserved: Check
    posix_credentials_preserved: Check
    posix_membership_preserved: Check
    credentials: Literal["ROOT", "LOCAL_USER", "OTHER"]
    audit_user: Literal["LOCAL_USER", "UNATTRIBUTED", "OTHER"]
    group: Literal["SELF", "PARENT", "OTHER"]
    session: Literal["SELF", "PARENT", "OTHER"]
    arguments: Literal[
        "APP_IMAGE_ONLY", "LOGIN_FP_USER", "ZSH_LOGIN", "BASH_LOGIN", "MARKER_SAMPLE", "OTHER"
    ]
    responsibility: Literal["SELF", "PARENT", "OTHER", "UNSET"]
    security: reference.NativeSecurityFacts
    slice: reference.NativeSliceFacts
    entitlements: reference.EntitlementShape
    stdio_kinds: tuple[Literal["VNODE", "PIPE", "SOCKET", "OTHER", "UNKNOWN"], ...]
    only_standard_descriptors: Check
    terminal: Literal["PRESENT", "ABSENT", "UNKNOWN"]
    cwd: Literal["ROOT", "HOME", "OTHER", "UNKNOWN"]
    script_absent: Check
    dyld_path_matches_target: Check
    environment_from_previous_exec: reference.EnvironmentDifference | None = None


class Report(Model):
    kit_version: Literal[1] = 1
    purpose: Literal["TERMINAL_STARTUP_CHAIN_DIAGNOSTIC"] = "TERMINAL_STARTUP_CHAIN_DIAGNOSTIC"
    collection: Literal["MARKER_AUTHENTICATED_LAUNCH_CHAIN_ONLY"] = (
        "MARKER_AUTHENTICATED_LAUNCH_CHAIN_ONLY"
    )
    reference_review: Literal["REQUIRED"] = "REQUIRED"
    gate_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    terminal: Terminal
    error: Literal[
        "NONE",
        "INPUT",
        "PLATFORM",
        "ROOT_USER",
        "LOCATION",
        "BUILD",
        "COLLECTOR",
        "LIMIT",
        "DATA",
        "INTERRUPTED",
        "IO",
        "INTERNAL",
        "TIMEOUT",
        "APP_START_NOT_OBSERVED",
        "AMBIGUOUS_MARKER",
    ] = "NONE"
    stage: Literal["SETUP_READY", "COLLECTOR_READY", "TERMINAL_READY", "COMPLETE", "ERROR"] = (
        "ERROR"
    )
    provenance: Check = "INCONCLUSIVE"
    target_platform: Check = "INCONCLUSIVE"
    collector_ready: Check = "INCONCLUSIVE"
    collector_cleanup: Check = "INCONCLUSIVE"
    bounded_collection: Check = "INCONCLUSIVE"
    sequence_continuity: Check = "INCONCLUSIVE"
    candidate_ring_evicted: bool = False
    app_exec_retained: Check = "INCONCLUSIVE"
    app_link: Literal["ANCESTRY", "RESPONSIBILITY", "NOT_OBSERVED"] = "NOT_OBSERVED"
    wire_profile: Literal["V11", "UNQUALIFIED", "MIXED", "NOT_OBSERVED"] = "NOT_OBSERVED"
    marker_exit_zero: Check = "INCONCLUSIVE"
    phases: tuple[Phase, ...] = Field(default=(), max_length=MAX_CHAIN_ROWS)
    unified_log: Literal["NOT_COLLECTED"] = "NOT_COLLECTED"


def _role(process: dict, marker: reference.Image) -> Role:
    if reference._owned(process, marker):
        return "MARKER"
    executable = process.get("executable")
    return ROLES.get(executable.get("path"), "OTHER") if type(executable) is dict else "OTHER"


def _matches_execution(left: dict, right: dict) -> bool:
    # Credentials may change without exec. PID version and birth identify the
    # same execution in this single bounded boot, as in the Finder reviewer.
    return reference._identity(left) == reference._identity(right)


def select_lineage(
    rows: list[dict], sample: int, app: reference.Image, *, responsibility_links: bool = False
) -> list[int]:
    """Prove marker ancestry before retaining any machine-wide candidate row.

    Walk same-task replacements first, then exact fork children and their
    parents. A token-only parent edge is limited to an earlier native exec in
    this bounded stream. No path prefix or PID-only relationship is accepted.
    """
    selected: set[int] = set()

    def visit(index: int) -> None:
        if index in selected:
            return
        if len(selected) >= MAX_CHAIN_ROWS:
            raise reference.PrivateError("LIMIT")
        selected.add(index)
        before = rows[index]["process"]
        previous = next(
            (
                i
                for i in range(index - 1, -1, -1)
                if rows[i]["event_type"] == 9
                and _matches_execution(rows[i]["event"]["exec"]["target"], before)
            ),
            None,
        )
        if previous is not None:
            visit(previous)
            return
        fork = next(
            (
                i
                for i in range(index - 1, -1, -1)
                if rows[i]["event_type"] == 11
                and _matches_execution(rows[i]["event"]["fork"]["child"], before)
            ),
            None,
        )
        if fork is not None:
            selected.add(fork)
            parent = rows[fork]["process"]
            previous = next(
                (
                    i
                    for i in range(fork - 1, -1, -1)
                    if rows[i]["event_type"] == 9
                    and _matches_execution(rows[i]["event"]["exec"]["target"], parent)
                ),
                None,
            )
        else:
            parent_token = reference._token(before, "parent_audit_token")
            previous = next(
                (
                    i
                    for i in range(index - 1, -1, -1)
                    if rows[i]["event_type"] == 9
                    and reference._token(rows[i]["event"]["exec"]["target"])[5::2]
                    == parent_token[5::2]
                ),
                None,
            )
        if previous is not None:
            visit(previous)

    visit(sample)
    if responsibility_links:
        for index in tuple(selected):
            if rows[index]["event_type"] != 9:
                continue
            responsible = reference._token(
                rows[index]["event"]["exec"]["target"], "responsible_audit_token"
            )
            owner = next(
                (
                    i
                    for i in range(index - 1, -1, -1)
                    if rows[i]["event_type"] == 9
                    and reference._owned(rows[i]["event"]["exec"]["target"], app)
                    and reference._token(rows[i]["event"]["exec"]["target"])[5::2]
                    == responsible[5::2]
                ),
                None,
            )
            if owner is not None:
                visit(owner)
    if not any(
        rows[i]["event_type"] == 9 and reference._owned(rows[i]["event"]["exec"]["target"], app)
        for i in selected
    ):
        return []
    if len(selected) > MAX_CHAIN_ROWS:
        raise reference.PrivateError("LIMIT")
    return sorted(selected)


class Tracker:
    """Bounded transient candidates; persist nothing until marker ancestry is proved."""

    def __init__(self, manifest: Manifest) -> None:
        self.manifest = manifest
        self.ring: deque[tuple[bytes, dict]] = deque()
        self.ring_bytes = 0
        self.total_bytes = 0
        self.evicted = False
        self.ready_pids: set[int] = set()
        self.ready_tokens: set[tuple[int, ...]] = set()
        self.ready = False
        self.collecting = False
        self.sequence: dict[int, int] = {}
        self.global_sequence = -1
        self.sequence_ok = True
        self.sample_count = 0
        self.sample_token: tuple[int, ...] | None = None
        self.sample_identity: tuple[int, int, int] | None = None
        self.retained: list[bytes] = []
        self.exit_zero: bool | None = None
        self.app_link: Literal["ANCESTRY", "RESPONSIBILITY", "NOT_OBSERVED"] = "NOT_OBSERVED"

    def accept(self, raw: bytes) -> list[tuple[str, bytes]]:
        self.total_bytes += len(raw)
        if self.total_bytes > reference.MAX_STREAM:
            raise reference.PrivateError("LIMIT")
        row = reference._decode(raw)
        kind, seq, glob = row.get("event_type"), row.get("seq_num"), row.get("global_seq_num")
        if (
            type(kind) is not int
            or kind not in (9, 11, 15)
            or type(seq) is not int
            or seq < 0
            or type(glob) is not int
            or glob < 0
        ):
            raise reference.PrivateError("DATA")
        if (
            kind in self.sequence and seq != self.sequence[kind] + 1
        ) or glob <= self.global_sequence:
            self.sequence_ok = False
        self.sequence[kind], self.global_sequence = seq, glob
        if kind == 9:
            payload = row["event"]["exec"]
            target = payload["target"]
            if reference._owned(target, self.manifest.marker):
                token = reference._token(target)
                if payload.get("args", [])[1:] == ["--ready"] and token[5] in self.ready_pids:
                    self.ready_tokens.add(token)
                if self.collecting and payload.get("args", [])[1:] == ["--sample"]:
                    self.sample_count += 1
                    self.sample_token = token
                    self.sample_identity = reference._identity(target)
                    candidates = [item[1] for item in self.ring] + [row]
                    indexes = select_lineage(candidates, len(candidates) - 1, self.manifest.app)
                    if indexes:
                        self.app_link = "ANCESTRY"
                    else:
                        indexes = select_lineage(
                            candidates,
                            len(candidates) - 1,
                            self.manifest.app,
                            responsibility_links=True,
                        )
                        self.app_link = "RESPONSIBILITY" if indexes else "NOT_OBSERVED"
                    raws = [item[0] for item in self.ring] + [raw]
                    self.retained = [raws[i] for i in indexes]
        elif kind == 15:
            token = reference._token(row["process"])
            if token in self.ready_tokens and row["event"]["exit"].get("stat") == 0:
                self.ready = True
            if (
                self.collecting
                and token == self.sample_token
                and reference._identity(row["process"]) == self.sample_identity
            ):
                self.exit_zero = row["event"]["exit"].get("stat") == 0
                if self.retained:
                    self.retained.append(raw)
        if self.collecting:
            self.ring.append((raw, row))
            self.ring_bytes += len(raw)
            while len(self.ring) > MAX_RING_ROWS or self.ring_bytes > MAX_RING_BYTES:
                removed, _ = self.ring.popleft()
                self.ring_bytes -= len(removed)
                self.evicted = True
        return []


def _check(value: bool) -> Check:
    return "PASS" if value else "FAIL"


def analyze(raws: list[bytes], manifest: Manifest) -> tuple[Phase, ...]:
    """Export only fixed ABI and relationship labels; never native text or IDs."""
    rows = [reference._decode(raw) for raw in raws]
    phases: list[Phase] = []
    previous_environment: tuple[bytes, ...] | None = None
    for row in rows:
        if row["event_type"] != 9:
            continue
        before, payload = row["process"], row["event"]["exec"]
        target = payload["target"]
        old, new = reference._token(before), reference._token(target)
        responsible, parent = (
            reference._token(target, "responsible_audit_token"),
            reference._token(target, "parent_audit_token"),
        )
        try:
            reference.decode_endpoint_security_record(json.dumps(row))
        except (ValueError, TypeError, ValidationError):
            shape: Check = "FAIL"
        else:
            shape = "PASS"
        fds = payload.get("fds")
        by_fd = (
            {item.get("fd"): item.get("fdtype") for item in fds if type(item) is dict}
            if type(fds) is list
            else {}
        )
        environment = payload.get("env")
        encoded_environment = (
            tuple(item.encode() for item in environment)
            if type(environment) is list and all(type(item) is str for item in environment)
            else ()
        )
        cwd = payload.get("cwd")
        cwd_path = cwd.get("path") if type(cwd) is dict else None
        role = _role(target, manifest.marker)
        args = payload.get("args")
        argument_shape = (
            "APP_IMAGE_ONLY"
            if role in ("APPLE_TERMINAL", "ITERM2") and args == [PATHS[manifest.terminal]]
            else "LOGIN_FP_USER"
            if role == "LOGIN"
            and args
            in (
                ["/usr/bin/login", "-fp", manifest.own_username],
                ["login", "-fp", manifest.own_username],
            )
            else "ZSH_LOGIN"
            if role == "ZSH" and args == ["-zsh"]
            else "BASH_LOGIN"
            if role == "BASH" and args == ["-bash"]
            else "MARKER_SAMPLE"
            if role == "MARKER" and type(args) is list and args[1:] == ["--sample"]
            else "OTHER"
        )
        phases.append(
            Phase(
                role=role,
                before_role=_role(before, manifest.marker),
                same_pid_replacement=_check(
                    old[5] == new[5]
                    and reference._birth(before) == reference._birth(target)
                    and old[7] != new[7]
                ),
                native_shape=shape,
                shape_excluding_entitlements=reference._shape_without_entitlements(row),
                fork_linkage="PASS"
                if any(
                    item["event_type"] == 11
                    and _matches_execution(item["event"]["fork"]["child"], before)
                    for item in rows
                )
                else "INCONCLUSIVE",
                audit_origin_preserved=_check((old[0], old[6]) == (new[0], new[6])),
                posix_credentials_preserved=_check(old[1:5] == new[1:5]),
                credentials="ROOT"
                if new[1:5] == (0, 0, 0, 0)
                else "LOCAL_USER"
                if new[1:5]
                == (manifest.own_uid, manifest.own_gid, manifest.own_uid, manifest.own_gid)
                else "OTHER",
                audit_user="LOCAL_USER"
                if new[0] == manifest.own_uid
                else "UNATTRIBUTED"
                if new[0] == 2**32 - 1
                else "OTHER",
                group="SELF"
                if target.get("group_id") == new[5]
                else "PARENT"
                if target.get("group_id") == parent[5]
                else "OTHER",
                session="SELF"
                if target.get("session_id") == new[5]
                else "PARENT"
                if target.get("session_id") == parent[5]
                else "OTHER",
                arguments=argument_shape,
                posix_membership_preserved=_check(
                    (before.get("group_id"), before.get("session_id"))
                    == (target.get("group_id"), target.get("session_id"))
                ),
                responsibility="SELF"
                if responsible == new
                else "PARENT"
                if responsible == parent
                else "UNSET"
                if not any(responsible)
                else "OTHER",
                security=reference.inspect_native_security(target),
                slice=reference.inspect_native_slice(payload),
                entitlements=reference.entitlement_shape(
                    payload.get("entitlements"), present="entitlements" in payload
                ),
                stdio_kinds=tuple(
                    {1: "VNODE", 2: "SOCKET", 6: "PIPE"}.get(
                        by_fd.get(fd), "UNKNOWN" if fd not in by_fd else "OTHER"
                    )
                    for fd in range(3)
                ),
                only_standard_descriptors=_check(
                    type(fds) is list
                    and len(fds) == 3
                    and set(by_fd) == {0, 1, 2}
                    and payload.get("last_fd") == 2
                ),
                terminal="UNKNOWN"
                if "tty" not in target
                else "ABSENT"
                if target["tty"] is None
                else "PRESENT",
                cwd="ROOT"
                if cwd_path == "/"
                else "HOME"
                if cwd_path == manifest.own_home
                else "UNKNOWN"
                if cwd_path is None
                else "OTHER",
                script_absent=_check(payload.get("script", "UNKNOWN") is None),
                dyld_path_matches_target=_check(
                    payload.get("dyld_exec_path") == target.get("executable", {}).get("path")
                ),
                environment_from_previous_exec=None
                if previous_environment is None
                else reference.compare_environment(previous_environment, encoded_environment),
            )
        )
        previous_environment = encoded_environment
    return tuple(phases)


def prepare(destination: Path | None = None) -> Path:
    """AGENT SAFE: copy code only, without running a command or reading logs."""
    source = Path(__file__).resolve()
    docs = source.parents[1] / "docs/design/macos-workstation-feasibility"
    parent = (destination.parent if destination else Path("/private/tmp")).resolve(strict=True)
    reference._outside_git(parent)
    root = (
        parent / destination.name
        if destination
        else Path(tempfile.mkdtemp(prefix="eforge-terminal-startup-kit-", dir=parent))
    )
    if destination:
        root.mkdir(mode=0o700)
    root.chmod(0o700)
    for original, name in (
        (source, CODE[0]),
        (Path(reference.__file__), CODE[1]),
        (docs / "terminal-startup-reference/terminal_marker.c", CODE[2]),
        (docs / "gui-launch-reference/collector_guard.c", CODE[3]),
        (docs / "terminal-startup-reference/PRIVATE-RUN.md", "PRIVATE-RUN.md"),
    ):
        shutil.copyfile(original, root / name)
        (root / name).chmod(0o600)
    return root


def _root() -> Path:
    root = Path(__file__).resolve().parent
    reference._outside_git(root)
    reference._directory(root)
    return root


def _image(path: Path) -> reference.Image:
    if not stat.S_ISREG(path.lstat().st_mode):
        raise reference.PrivateError("BUILD")
    return reference._image(path)


def setup(terminal: Terminal) -> Report:
    """HUMAN ONLY: compile/sign the marker and guard; launch nothing."""
    root = _root()
    os_version, os_build = reference._preflight()
    reference._write(root / "SETUP-LOCK", b"SETUP\n")
    for source, output in ((CODE[2], "terminal-marker"), (CODE[3], "collector-guard")):
        reference._command(
            [
                "/usr/bin/clang",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(root / source),
                "-o",
                str(root / output),
            ],
            root,
        )
        (root / output).chmod(0o700)
    reference._command(
        ["/usr/bin/codesign", "--force", "--sign", "-", str(root / "terminal-marker")], root
    )
    account = pwd.getpwuid(os.getuid())
    manifest = Manifest(
        terminal=terminal,
        os_version=os_version,
        os_build=os_build,
        app=_image(Path(PATHS[terminal])),
        marker=_image(root / "terminal-marker"),
        guard_sha256=reference._digest(root / "collector-guard"),
        codec_sha256=reference._codec_digest(),
        code_sha256={name: reference._digest(root / name) for name in CODE},
        own_uid=account.pw_uid,
        own_gid=account.pw_gid,
        own_username=account.pw_name,
        own_home=account.pw_dir,
    )
    reference._write(root / "SETUP.json", manifest.model_dump_json().encode())
    return Report(terminal=terminal, stage="SETUP_READY", provenance="PASS", target_platform="PASS")


def _manifest(root: Path) -> Manifest:
    manifest = Manifest.model_validate_json(reference._read(root / "SETUP.json"))
    if (
        manifest.app != _image(Path(PATHS[manifest.terminal]))
        or manifest.marker != _image(root / "terminal-marker")
        or manifest.guard_sha256 != reference._digest(root / "collector-guard")
        or manifest.codec_sha256 != reference._codec_digest()
        or manifest.code_sha256 != {name: reference._digest(root / name) for name in CODE}
    ):
        raise reference.PrivateError("BUILD")
    return manifest


def _failure(error: BaseException) -> str:
    """Map failures to the fixed export vocabulary without exception text."""
    if isinstance(error, reference.PrivateError):
        return (
            error.code
            if error.code in Report.model_fields["error"].annotation.__args__
            else "INTERNAL"
        )
    if isinstance(error, KeyboardInterrupt):
        return "INTERRUPTED"
    if isinstance(error, (OSError, subprocess.SubprocessError)):
        return "IO"
    return "DATA"


def capture() -> Report:
    """HUMAN ONLY: observe a manually opened terminal, anchored by its marker."""
    root = _root()
    os_version, os_build = reference._preflight()
    manifest = _manifest(root)
    if (manifest.os_version, manifest.os_build) != (os_version, os_build):
        raise reference.PrivateError("PLATFORM")
    reference._write(root / "SESSION-LOCK", b"ACTIVE\n")
    run = root / f"run-{uuid.uuid4().hex}"
    run.mkdir(mode=0o700)
    reference._write(root / "ACTIVE-RUN", (run.name + "\n").encode())
    reference._write(run / "provenance.json", manifest.model_dump_json().encode())
    report = Report(terminal=manifest.terminal, provenance="PASS", target_platform="PASS")
    tracker = Tracker(manifest)
    collector: subprocess.Popen[bytes] | None = None
    probes: list[subprocess.Popen[bytes]] = []
    pump: reference.Pump | None = None
    try:
        collector = subprocess.Popen(
            ["/usr/bin/sudo", "-n", str(root / "collector-guard")],
            env=reference.SAFE_ENV,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        pump = reference.Pump(collector, tracker, {})
        deadline, next_probe = time.monotonic() + 10, 0.0
        while time.monotonic() < deadline and not tracker.ready:
            if time.monotonic() >= next_probe and len(probes) < 8:
                probe = reference._start(root / "terminal-marker", "--ready")
                probes.append(probe)
                tracker.ready_pids.add(probe.pid)
                next_probe = time.monotonic() + 1
            pump.tick()
        if not tracker.ready:
            raise reference.PrivateError("COLLECTOR")
        report = report.model_copy(update={"stage": "TERMINAL_READY", "collector_ready": "PASS"})
        print(report.model_dump_json(include={"purpose", "stage", "error", "terminal"}), flush=True)
        tracker.collecting = True
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and tracker.exit_zero is None:
            pump.tick()
        _manifest(root)
        report = report.model_copy(
            update={
                "stage": "COMPLETE",
                "bounded_collection": "PASS",
                "sequence_continuity": _check(tracker.sequence_ok),
                "candidate_ring_evicted": tracker.evicted,
                "app_exec_retained": _check(bool(tracker.retained)),
                "app_link": tracker.app_link,
                "wire_profile": reference._wire_profile(tracker.retained),
                "marker_exit_zero": _check(tracker.exit_zero is True),
                "error": "TIMEOUT"
                if tracker.exit_zero is None
                else "AMBIGUOUS_MARKER"
                if tracker.sample_count != 1
                else "APP_START_NOT_OBSERVED"
                if not tracker.retained
                else "NONE",
            }
        )
    except (
        reference.PrivateError,
        KeyboardInterrupt,
        OSError,
        subprocess.SubprocessError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        AttributeError,
        RecursionError,
    ) as error:
        report = report.model_copy(update={"stage": "ERROR", "error": _failure(error)})
    finally:
        cleanup = reference._stop_collector(collector) if collector is not None else False
        if pump is not None:
            pump.selector.close()
        for probe in probes:
            reference._stop_probe(probe)
        if collector is not None and collector.stdout is not None:
            collector.stdout.close()
    report = report.model_copy(update={"collector_cleanup": _check(cleanup)})
    # Raw rows never reach a file until the exact marker-to-app chain is proved.
    if report.error == "NONE" and cleanup:
        try:
            report = report.model_copy(update={"phases": analyze(tracker.retained, manifest)})
            reference._write(
                run / "launch-chain-events.jsonl", b"\n".join(tracker.retained) + b"\n"
            )
        except (
            ValueError,
            TypeError,
            KeyError,
            IndexError,
            AttributeError,
            RecursionError,
        ) as error:
            report = report.model_copy(update={"stage": "ERROR", "error": _failure(error)})
    elif report.error == "NONE":
        report = report.model_copy(update={"stage": "ERROR", "error": "COLLECTOR"})
    reference._write(run / "SHAREABLE-REPORT.json", report.model_dump_json(indent=2).encode())
    return report


def report_existing() -> Report:
    """HUMAN ONLY: replay the fixed saved report, without opening native records."""
    root = _root()
    run = reference._active(root)
    return Report.model_validate_json(reference._read(run / "SHAREABLE-REPORT.json"))


def main() -> None:
    """Keep every user-visible failure inside a fixed diagnostic vocabulary."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "setup", "capture", "report"))
    parser.add_argument("--terminal", choices=("apple", "iterm2"), default="apple")
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--private-run", action="store_true")
    parser.add_argument("--fresh-launch", action="store_true")
    args = parser.parse_args()
    if args.operation == "prepare":
        print(prepare(args.destination))
        return
    report = Report(terminal=args.terminal, error="INPUT")
    try:
        if not args.private_run or (args.operation == "capture" and not args.fresh_launch):
            raise reference.PrivateError("INPUT")
        report = (
            setup(args.terminal)
            if args.operation == "setup"
            else capture()
            if args.operation == "capture"
            else report_existing()
        )
    except reference.PrivateError as error:
        code = (
            error.code
            if error.code in Report.model_fields["error"].annotation.__args__
            else "INTERNAL"
        )
        report = report.model_copy(update={"error": code})
    except KeyboardInterrupt:
        report = report.model_copy(update={"error": "INTERRUPTED"})
    except (OSError, subprocess.SubprocessError):
        report = report.model_copy(update={"error": "IO"})
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError):
        report = report.model_copy(update={"error": "DATA"})
    print(report.model_dump_json(indent=2), flush=True)


if __name__ == "__main__":
    main()
