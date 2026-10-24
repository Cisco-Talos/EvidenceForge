# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Human-run, private ES reference experiment; never run capture in an agent session.

Only prepare/help and invented-input tests are appropriate for agent execution.
Live records stay in the human's process and outside Git. No exception or native
value is interpolated into diagnostics. This is evidence acquisition, not source
admission or an automatic ES-R1 pass.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import logging
import os
import platform
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from evidenceforge.formats.macos_endpoint_security import (
    ESAction,
    ESExecEvent,
    ESExitEvent,
    ESForkEvent,
    ESProcess,
    ESThread,
    NativeTime,
    UInt64,
)

logger = logging.getLogger(__name__)

MAX_LINE_BYTES = 1_048_576
MAX_RECORDS = 100_000
MAX_RETAINED = 32
CAPTURE_SECONDS = 15.0
SAFE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
SOURCES = (
    Path(__file__).resolve().parents[1]
    / "docs/design/macos-workstation-feasibility/native-reference-capture"
)
type Check = Literal["PASS", "FAIL", "INCONCLUSIVE"]
type ErrorCode = Literal[
    "NONE",
    "INPUT",
    "PLATFORM",
    "LOCATION",
    "BUILD",
    "COLLECTOR",
    "DATA",
    "INTERRUPTED",
    "INTERNAL",
    "ROOT_USER",
    "OS_FAMILY",
    "PYTHON_ARCH",
    "OS_MAJOR",
    "OS_VERSION",
    "WIRE_PROFILE",
]
type WireProfile = Literal[
    "NOT_OBSERVED",
    "V10_CANDIDATE",
    "V11_UNQUALIFIED",
    "OTHER_UNQUALIFIED",
    "SCHEMA_UNQUALIFIED",
    "MIXED",
    "INVALID",
]


class PrivateCaptureError(ValueError):
    """A fixed diagnostic code with no native values or exception text."""

    def __init__(self, code: ErrorCode) -> None:
        self.code = code
        super().__init__(code)


class Report(BaseModel):
    """The entire export vocabulary: no strings supplied by the host or records."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    kit_version: Literal[1, 2] = 2
    reference_review: Literal["REQUIRED"] = "REQUIRED"
    gate_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    error: ErrorCode = "NONE"
    target_platform: Check = "INCONCLUSIVE"
    wire_profile: WireProfile = "NOT_OBSERVED"
    message_shapes: Check = "INCONCLUSIVE"
    probe_controls: Check = "INCONCLUSIVE"
    bounded_delivery: Check = "INCONCLUSIVE"
    candidate_v10_shapes: Check = "INCONCLUSIVE"
    fork_exec_exit_linkage: Check = "INCONCLUSIVE"
    controlled_exec_inputs: Check = "INCONCLUSIVE"
    controlled_descriptors: Check = "INCONCLUSIVE"
    exit_status_agreement: Check = "INCONCLUSIVE"
    failed_exec_control: Check = "INCONCLUSIVE"
    sequence_continuity: Check = "INCONCLUSIVE"


class Identity(BaseModel):
    """Private process incarnation, never exported or reduced to a PID alone."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    pid: int = Field(gt=0)
    pidversion: int = Field(ge=0)
    start_time: str


class Control(BaseModel):
    """An independently observed probe wait/failed-exec result, kept private."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    kind: Literal["wait", "failed_return"]
    case: Literal["exit7", "signal", "failed_exec", "apple_true"]
    pid: int = Field(gt=0)
    value: int


class PrivateProvenance(BaseModel):
    """Private collection context; never included in the public report."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    kit_version: Literal[2] = 2
    os_version: str
    os_build: str
    architecture: Literal["arm64"] = "arm64"
    started: str
    ended: str
    collector: tuple[str, ...] = ("/usr/bin/eslogger", "fork", "exec", "exit")
    source_sha256: str
    binary_sha256: str
    wire_profile: WireProfile
    message_versions: tuple[int, ...]
    preservation: str = "Only exact probe family retained; raw matched rows unmodified; ambient rows discarded in memory."


class CandidateRecord(BaseModel):
    """Candidate v10 envelope, deliberately separate from production admission."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    schema_version: Literal[1]
    version: Literal[10]
    event_type: Literal[9, 11, 15]
    action_type: Literal[1]
    action: ESAction
    time: NativeTime
    mach_time: UInt64
    seq_num: UInt64
    global_seq_num: UInt64
    thread: ESThread
    process: ESProcess
    event: ESExecEvent | ESForkEvent | ESExitEvent

    @field_validator("schema_version", "version", "event_type", "action_type", mode="before")
    @classmethod
    def integer_tags(cls, value: object) -> object:
        """Reject booleans that compare equal to literal integer discriminants."""
        if type(value) is not int:
            raise ValueError("DATA")
        return value

    @field_validator("time")
    @classmethod
    def calendar_time(cls, value: str) -> str:
        """Check the native timestamp without exporting it."""
        datetime.fromisoformat(value)
        return value


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PrivateCaptureError("DATA")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise PrivateCaptureError("DATA")


def _decode(raw: bytes) -> dict[str, object]:
    if len(raw) > MAX_LINE_BYTES:
        raise PrivateCaptureError("DATA")
    value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_reject_constant)
    if not isinstance(value, dict):
        raise PrivateCaptureError("DATA")
    return value


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise PrivateCaptureError("DATA")
    return value


def _identity(process: object) -> Identity:
    view = _mapping(process)
    token = view.get("audit_token")
    if not isinstance(token, list) or len(token) != 8:
        raise PrivateCaptureError("DATA")
    if any(type(word) is not int or not 0 <= word <= 0xFFFFFFFF for word in token):
        raise PrivateCaptureError("DATA")
    return Identity(pid=token[5], pidversion=token[7], start_time=view.get("start_time"))


def _executable(process: object) -> object:
    return _mapping(_mapping(process).get("executable")).get("path")


def _candidate_shape(raw: bytes) -> bool:
    try:
        record = CandidateRecord.model_validate_json(raw)
        expected = {9: ESExecEvent, 11: ESForkEvent, 15: ESExitEvent}[record.event_type]
        if type(record.event) is not expected:
            return False
        processes = [record.process]
        if isinstance(record.event, ESForkEvent):
            processes.append(record.event.fork.child)
        elif isinstance(record.event, ESExecEvent):
            processes.append(record.event.exec.target)
            if not isinstance(record.event.exec.dyld_exec_path, str):
                return False
        return all(
            all(
                isinstance(token, tuple)
                for token in (
                    process.audit_token,
                    process.parent_audit_token,
                    process.responsible_audit_token,
                )
            )
            and process.cs_validation_category is not None
            for process in processes
        )
    except ValidationError:
        return False


class StreamFilter:
    """Retain only the probe's exact fork/exec/exit identities before disk writes."""

    def __init__(self, root_pid: int, probe: Path) -> None:
        self.root_pid = root_pid
        self.probe = str(probe)
        self.root: Identity | None = None
        self.live: dict[int, Identity] = {}
        self.executables: dict[int, str] = {}
        self.records: list[dict[str, object]] = []
        self.last_sequence: dict[int, int] = {}
        self.last_global: int | None = None
        self.sequence_ok = True
        self.shapes_ok = True
        self.total = 0

    @property
    def wire_profile(self) -> WireProfile:
        """Classify matched headers without exporting native values or coercing versions."""
        if not self.records:
            return "NOT_OBSERVED"
        profiles: set[tuple[int, int]] = set()
        for record in self.records:
            schema, version = record.get("schema_version"), record.get("version")
            if type(schema) is not int or type(version) is not int or schema <= 0 or version <= 0:
                return "INVALID"
            profiles.add((schema, version))
        if len(profiles) != 1:
            return "MIXED"
        schema, version = next(iter(profiles))
        if schema != 1:
            return "SCHEMA_UNQUALIFIED"
        if version == 10:
            return "V10_CANDIDATE"
        if version == 11:
            return "V11_UNQUALIFIED"
        return "OTHER_UNQUALIFIED"

    def accept(self, raw: bytes) -> bool:
        """Inspect in local memory; false means discard without saving the record."""
        self.total += 1
        if self.total > MAX_RECORDS:
            raise PrivateCaptureError("DATA")
        record = _decode(raw)
        event_type = record.get("event_type")
        if type(event_type) is not int or event_type not in (9, 11, 15):
            raise PrivateCaptureError("DATA")
        seq = record.get("seq_num")
        if type(seq) is not int or seq < 0:
            raise PrivateCaptureError("DATA")
        previous = self.last_sequence.get(event_type)
        if previous is not None and seq != previous + 1:
            self.sequence_ok = False
        self.last_sequence[event_type] = seq
        global_seq = record.get("global_seq_num")
        if type(global_seq) is not int or global_seq < 0:
            raise PrivateCaptureError("DATA")
        if self.last_global is not None and global_seq <= self.last_global:
            self.sequence_ok = False
        self.last_global = global_seq

        process = record.get("process")
        try:
            identity = _identity(process)
        except (PrivateCaptureError, ValidationError):
            # Unsupported ambient shapes cannot become retained records. Missing
            # probe identities will make the bounded lifecycle checks fail.
            return False
        if self.root is None:
            if (
                event_type != 11
                or identity.pid != self.root_pid
                or _executable(process) != self.probe
            ):
                return False
            self.root = identity
            self.live[identity.pid] = identity
            self.executables[identity.pid] = self.probe
        if self.live.get(identity.pid) != identity:
            return False
        if _executable(process) != self.executables[identity.pid]:
            raise PrivateCaptureError("DATA")

        event = _mapping(record.get("event"))
        if event_type == 11:
            if identity != self.root or _executable(process) != self.probe:
                raise PrivateCaptureError("DATA")
            child = _mapping(_mapping(event.get("fork")).get("child"))
            child_identity = _identity(child)
            if child_identity.pid in self.live or _executable(child) != self.probe:
                raise PrivateCaptureError("DATA")
            self.live[child_identity.pid] = child_identity
            self.executables[child_identity.pid] = self.probe
        elif event_type == 9:
            target = _mapping(_mapping(event.get("exec")).get("target"))
            target_identity = _identity(target)
            if (
                identity == self.root
                or target_identity.pid != identity.pid
                or target_identity.start_time != identity.start_time
                or _executable(target) not in (self.probe, "/usr/bin/true")
            ):
                raise PrivateCaptureError("DATA")
            self.live[identity.pid] = target_identity
            self.executables[identity.pid] = str(_executable(target))
        else:
            del self.live[identity.pid]
            del self.executables[identity.pid]
        if len(self.records) >= MAX_RETAINED:
            raise PrivateCaptureError("DATA")
        # Only select a full candidate validator for its actual known header.
        # Unknown versions remain acquisition evidence, not inputs to a v10 codec.
        schema, version = record.get("schema_version"), record.get("version")
        if type(schema) is int and schema == 1 and type(version) is int and version == 10:
            self.shapes_ok &= _candidate_shape(raw)
        self.records.append(record)
        return True


def analyze(tracker: StreamFilter, controls: list[Control], complete: bool) -> Report:
    """Return only fixed checks; retain every host-derived value locally."""
    waits = {item.case: item for item in controls if item.kind == "wait"}
    failed = [item for item in controls if item.kind == "failed_return"]
    expected = {"exit7": 7 << 8, "signal": 15, "failed_exec": 3 << 8, "apple_true": 0}
    controls_ok = (
        len(controls) == 5
        and len(waits) == 4
        and len({item.pid for item in waits.values()}) == 4
        and all(waits[key].value == value for key, value in expected.items() if key in waits)
        and len(failed) == 1
        and failed[0].case == "failed_exec"
        and failed[0].value == errno.ENOENT
        and "failed_exec" in waits
        and failed[0].pid == waits["failed_exec"].pid
    )
    linkage = controls_ok
    statuses = controls_ok
    failed_ok = controls_ok
    inputs_ok = controls_ok
    descriptors_ok = controls_ok
    for case, wait in waits.items():
        forks = [
            row
            for row in tracker.records
            if row["event_type"] == 11
            and _identity(_mapping(_mapping(row["event"])["fork"])["child"]).pid == wait.pid
        ]
        execs = [
            row
            for row in tracker.records
            if row["event_type"] == 9 and _identity(row["process"]).pid == wait.pid
        ]
        exits = [
            row
            for row in tracker.records
            if row["event_type"] == 15 and _identity(row["process"]).pid == wait.pid
        ]
        linkage &= (
            len(forks) == 1
            and len(exits) == 1
            and len(execs) == (0 if case == "failed_exec" else 1)
        )
        if len(forks) == len(exits) == 1:
            chain = [forks[0], *execs, exits[0]]
            ticks = [row.get("mach_time") for row in chain]
            linkage &= all(type(tick) is int for tick in ticks) and ticks == sorted(ticks)
            parent_token = _mapping(forks[0]["process"]).get("audit_token")
            child_views = [
                _mapping(_mapping(_mapping(forks[0]["event"])["fork"])["child"]),
                _mapping(exits[0]["process"]),
            ]
            for execution_row in execs:
                before = _mapping(execution_row["process"])
                after = _mapping(_mapping(_mapping(execution_row["event"])["exec"])["target"])
                child_views.extend((before, after))
                before_token = before.get("audit_token")
                after_token = after.get("audit_token")
                linkage &= (
                    isinstance(before_token, list)
                    and isinstance(after_token, list)
                    and before_token[:7] == after_token[:7]
                    and before.get("group_id") == after.get("group_id")
                    and before.get("session_id") == after.get("session_id")
                )
            linkage &= all(
                view.get("ppid") == tracker.root_pid
                and view.get("parent_audit_token") == parent_token
                for view in child_views
            )
        if len(exits) == 1:
            statuses &= _mapping(_mapping(exits[0]["event"])["exit"]).get("stat") == wait.value
        else:
            statuses = False
        if case != "failed_exec":
            if len(execs) == 1:
                execution = _mapping(_mapping(execs[0]["event"])["exec"])
                target_path = "/usr/bin/true" if case == "apple_true" else tracker.probe
                args = [target_path] if case == "apple_true" else [target_path, case]
                env = execution.get("env")
                inputs_ok &= (
                    execution.get("args") == args
                    and isinstance(env, list)
                    and len(env) == len(SAFE_ENV)
                    and all(isinstance(item, str) for item in env)
                    and set(env) == {f"{key}={value}" for key, value in SAFE_ENV.items()}
                    and _mapping(execution.get("cwd")).get("path")
                    == str(Path(tracker.probe).parent)
                    and _executable(execution.get("target")) == target_path
                )
                descriptors = execution.get("fds")
                descriptors_ok &= (
                    isinstance(descriptors, list)
                    and len(descriptors) == 3
                    and {
                        _mapping(item).get("fd"): _mapping(item).get("fdtype")
                        for item in descriptors
                    }
                    == {0: 6, 1: 1, 2: 1}
                    and execution.get("last_fd") == 2
                )
            else:
                inputs_ok = False
                descriptors_ok = False
        if case == "failed_exec":
            failed_ok &= not execs and len(exits) == 1
    delivery = complete and controls_ok and linkage and not tracker.live
    profile = tracker.wire_profile
    shapes: Check = "INCONCLUSIVE"
    if profile == "V10_CANDIDATE":
        shapes = "PASS" if tracker.shapes_ok else "FAIL"
    elif profile == "INVALID":
        shapes = "FAIL"
    unqualified = profile not in ("NOT_OBSERVED", "V10_CANDIDATE")
    return Report(
        error="WIRE_PROFILE" if unqualified else "NONE",
        target_platform="PASS",
        wire_profile=profile,
        message_shapes=shapes,
        probe_controls="PASS" if controls_ok else "FAIL",
        bounded_delivery="PASS" if delivery else "FAIL",
        candidate_v10_shapes=shapes if profile == "V10_CANDIDATE" else "INCONCLUSIVE",
        fork_exec_exit_linkage="PASS" if linkage else "FAIL",
        controlled_exec_inputs="PASS" if inputs_ok else "FAIL",
        controlled_descriptors="PASS" if descriptors_ok else "FAIL",
        exit_status_agreement="PASS" if statuses else "FAIL",
        failed_exec_control="PASS" if failed_ok else "FAIL",
        sequence_continuity="PASS" if tracker.sequence_ok and tracker.records else "FAIL",
    )


def _outside_git(path: Path) -> None:
    if any(
        (parent / ".git").exists() or (parent / ".git").is_symlink()
        for parent in (path, *path.parents)
    ):
        raise PrivateCaptureError("LOCATION")


def prepare(destination: Path | None) -> Path:
    """Copy reviewed code/instructions only; never build, collect, or read host data."""
    parent = (destination.parent if destination else Path("/private/tmp")).resolve(strict=True)
    _outside_git(parent)
    if destination:
        target = parent / destination.name
        target.mkdir(mode=0o700)
    else:
        target = Path(tempfile.mkdtemp(prefix="eforge-native-reference-kit-", dir=parent))
    shutil.copyfile(Path(__file__).resolve(), target / "private_capture.py")
    shutil.copyfile(SOURCES / "process_probe.c", target / "process_probe.c")
    shutil.copyfile(SOURCES / "PRIVATE-RUN.md", target / "PRIVATE-RUN.md")
    for item in target.iterdir():
        item.chmod(0o600)
    return target


def _private_file(path: Path) -> BinaryIO:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    return os.fdopen(descriptor, "wb")


def _quiet_command(args: list[str], cwd: Path) -> bytes:
    result = subprocess.run(
        args,
        cwd=cwd,
        env=SAFE_ENV,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=True,
    )
    return result.stdout


def _stop_collector(collector: subprocess.Popen[bytes]) -> bool:
    if collector.poll() is None:
        collector.send_signal(signal.SIGINT)
        try:
            collector.wait(timeout=2)
        except subprocess.TimeoutExpired:
            collector.terminate()
            try:
                collector.wait(timeout=2)
            except subprocess.TimeoutExpired:
                collector.kill()
                collector.wait(timeout=2)
            return False
    return collector.returncode in (0, -signal.SIGINT, 128 + signal.SIGINT)


def _collect(work: Path, probe: Path) -> tuple[StreamFilter, list[Control], bool]:
    collector: subprocess.Popen[bytes] | None = None
    child: subprocess.Popen[bytes] | None = None
    complete = False
    with (
        _private_file(work / "probe-controls.jsonl") as protocol,
        _private_file(work / "probe-events.jsonl") as native,
    ):
        try:
            collector = subprocess.Popen(
                ["/usr/bin/sudo", "-n", "/usr/bin/eslogger", "fork", "exec", "exit"],
                cwd=work,
                env=SAFE_ENV,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                bufsize=0,
                # Retain the human Terminal's controlling TTY so sudo -n can
                # use their sudo -v ticket. sudo forwards our stop signal.
                start_new_session=False,
            )
            # eslogger exposes no readiness handshake. Give startup a bounded
            # head start; missing the first fork still fails the delivery check.
            time.sleep(0.5)
            if collector.poll() is not None:
                raise PrivateCaptureError("COLLECTOR")
            child = subprocess.Popen(
                [str(probe)],
                cwd=work,
                env=SAFE_ENV,
                stdin=subprocess.PIPE,
                stdout=protocol,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
            tracker = StreamFilter(child.pid, probe)
            assert child.stdin is not None and collector.stdout is not None
            # The C harness cannot fork until membership is initialized above.
            child.stdin.write(b"G")
            child.stdin.close()
            deadline = time.monotonic() + CAPTURE_SECONDS
            buffer = b""
            with selectors.DefaultSelector() as selector:
                selector.register(collector.stdout, selectors.EVENT_READ)
                while time.monotonic() < deadline:
                    if collector.poll() is not None:
                        break
                    for key, _mask in selector.select(timeout=0.1):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            break
                        buffer += chunk
                        while b"\n" in buffer:
                            line, buffer = buffer.split(b"\n", 1)
                            if line.strip() and tracker.accept(line):
                                native.write(line + b"\n")
                        if len(buffer) > MAX_LINE_BYTES:
                            raise PrivateCaptureError("DATA")
                    if child.poll() == 0 and tracker.root is not None and not tracker.live:
                        complete = not buffer.strip()
                        break
            complete &= _stop_collector(collector)
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=2)
        finally:
            try:
                if collector is not None:
                    try:
                        _stop_collector(collector)
                    finally:
                        if collector.stdout is not None:
                            collector.stdout.close()
            finally:
                if child is not None and child.poll() is None:
                    child.kill()
                    child.wait(timeout=2)
    controls: list[Control] = []
    with (work / "probe-controls.jsonl").open("rb") as source:
        while line := source.readline(MAX_LINE_BYTES + 1):
            if len(controls) >= 5:
                raise PrivateCaptureError("DATA")
            controls.append(Control.model_validate(_decode(line)))
    return tracker, controls, complete


def _check_target(kit: Path) -> str:
    """Check privately; return the local version or raise a fixed reason code."""
    _outside_git(kit)
    if platform.system() != "Darwin":
        raise PrivateCaptureError("OS_FAMILY")
    if os.geteuid() == 0:
        raise PrivateCaptureError("ROOT_USER")
    if platform.machine() != "arm64":
        raise PrivateCaptureError("PYTHON_ARCH")
    if kit.stat().st_mode & 0o077:
        raise PrivateCaptureError("LOCATION")
    version = _quiet_command(["/usr/bin/sw_vers", "-productVersion"], kit).decode().strip()
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,2}", version) is None:
        raise PrivateCaptureError("OS_VERSION")
    return version


def preflight() -> Report:
    """HUMAN ONLY: check the target without compiling, collecting or writing data."""
    _check_target(Path(__file__).resolve().parent)
    return Report(target_platform="PASS")


def capture() -> Report:
    """Run only on the human's command, privately, outside Git and agent tools."""
    kit = Path(__file__).resolve().parent
    version = _check_target(kit)
    work = Path(tempfile.mkdtemp(prefix="private-run-", dir=kit))
    source = kit / "process_probe.c"
    probe = work / "process-probe"
    started = datetime.now(UTC).isoformat()
    try:
        _quiet_command(["/usr/bin/xcode-select", "-p"], work)
        _quiet_command(
            [
                "/usr/bin/clang",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(source),
                "-o",
                str(probe),
            ],
            work,
        )
    except (OSError, subprocess.SubprocessError):
        raise PrivateCaptureError("BUILD") from None
    tracker, controls, complete = _collect(work, probe)
    report = analyze(tracker, controls, complete)
    provenance = PrivateProvenance(
        os_version=version,
        os_build=_quiet_command(["/usr/bin/sw_vers", "-buildVersion"], kit).decode().strip(),
        started=started,
        ended=datetime.now(UTC).isoformat(),
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        binary_sha256=hashlib.sha256(probe.read_bytes()).hexdigest(),
        wire_profile=tracker.wire_profile,
        message_versions=tuple(
            sorted(
                {
                    row["version"]
                    for row in tracker.records
                    if type(row.get("version")) is int and row["version"] > 0
                }
            )
        ),
    )
    with _private_file(work / "private-provenance.json") as output:
        output.write(provenance.model_dump_json(indent=2).encode() + b"\n")
    with _private_file(work / "SHAREABLE-REPORT.json") as output:
        output.write(report.model_dump_json(indent=2).encode() + b"\n")
    return report


class QuietParser(argparse.ArgumentParser):
    """Never echo user-supplied arguments in an error."""

    def error(self, _message: str) -> None:
        raise PrivateCaptureError("INPUT")


def _emit(report: Report) -> None:
    sys.stdout.write(report.model_dump_json(indent=2) + "\n")


def main(argv: list[str] | None = None) -> int:
    """Prepare code or execute an explicitly selected private native test."""
    parser = QuietParser(prog="private-es-reference", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True, parser_class=QuietParser)
    stage = commands.add_parser("prepare", help="Copy code only; does not collect or build")
    stage.add_argument("--destination", type=Path)
    commands.add_parser("preflight", help="HUMAN ONLY: private target check; no collection")
    run = commands.add_parser("capture", help="HUMAN ONLY: run privately after closing Codex")
    run.add_argument("--private-run", action="store_true", required=True)
    try:
        args = parser.parse_args(argv)
        if args.command == "prepare":
            print(prepare(args.destination))
            return 0
        report = preflight() if args.command == "preflight" else capture()
        _emit(report)
        return (
            0
            if report.error == "NONE"
            and all(value != "FAIL" for value in report.model_dump().values())
            else 1
        )
    except PrivateCaptureError as error:
        _emit(Report(error=error.code))
    except KeyboardInterrupt:
        _emit(Report(error="INTERRUPTED"))
        return 130
    except (OSError, ValueError, TypeError, KeyError, RecursionError, subprocess.SubprocessError):
        _emit(Report(error="INTERNAL"))
    return 2


def _private_exception_hook(_kind: object, _value: object, _traceback: object) -> None:
    # An unexpected bug must not print captured locals, native values or paths.
    # This hook deliberately ignores the exception, including its string/repr.
    os.write(2, b"PRIVATE_REFERENCE_INTERNAL_ERROR\n")


if __name__ == "__main__":
    sys.excepthook = _private_exception_hook
    raise SystemExit(main())
