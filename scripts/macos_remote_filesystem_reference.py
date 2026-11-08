# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Standalone Python 3.9+ second-host filesystem reference runner.

Only the user-authorized second host may execute capture. Local tests use invented
records. Raw evidence stays in a new owner-only remote run directory. Stdout is a
fixed technical report; exception text, native values and ambient rows never leave
the runner. This does not enable a production native file-event capability.

The stdlib dataclasses at this standalone transport boundary avoid requiring the
project's Python 3.12/Pydantic runtime on the reference Mac.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import BinaryIO

GUARD = Path("/Library/PrivilegedHelperTools/org.evidenceforge.reference-collector")
TOKEN_KEYS = ("auid", "euid", "egid", "ruid", "rgid", "pid", "asid", "pidversion")
FAMILIES = ("create", "close", "rename", "unlink", "exit")
EVENT_TYPES = {"create": 13, "close": 12, "rename": 25, "unlink": 32, "exit": 15}
NAMES = frozenset(("ready", "alpha", "fresh", "candidate", "victim"))
MAX_LINE = 1_048_576
MAX_RECORDS = 100_000
MAX_RETAINED_RECORDS = 10_000
MAX_RETAINED_BYTES = 64 * 1024 * 1024
SAFE_ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}


class RemoteReferenceError(ValueError):
    """Failure text consists only of closed codes created by this module."""


def decode(raw: bytes) -> dict:
    """Decode a bounded object, rejecting duplicate keys and non-JSON constants."""
    if len(raw) > MAX_LINE:
        raise RemoteReferenceError("LINE_LIMIT")

    def pairs(items: list[tuple[str, object]]) -> dict:
        result: dict = {}
        for key, value in items:
            if key in result:
                raise RemoteReferenceError("JSON")
            result[key] = value
        return result

    def constant(_value: str) -> None:
        raise RemoteReferenceError("JSON")

    try:
        result = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise RemoteReferenceError("JSON") from exc
    if type(result) is not dict:
        raise RemoteReferenceError("JSON")
    return result


def token_words(value: object) -> tuple[int, ...] | None:
    """Read exact native token words without accepting PID-only matches."""
    if type(value) is dict and set(value) == set(TOKEN_KEYS):
        value = [value[key] for key in TOKEN_KEYS]
    if type(value) is not list or len(value) != 8:
        return None
    if any(type(word) is not int or not 0 <= word <= 0xFFFFFFFF for word in value):
        return None
    return tuple(value)


def file_key(value: object) -> tuple[int, int] | None:
    """Read a native device/inode pair; do not infer one from a path."""
    if type(value) is not dict or type(value.get("stat")) is not dict:
        return None
    data = value["stat"]
    dev, ino = data.get("st_dev"), data.get("st_ino")
    return (dev, ino) if type(dev) is int and type(ino) is int else None


@dataclass
class Tracker:
    """Bounded filter authenticated by the controlled process's self observation."""

    control: dict
    image_path: str
    root_path: str
    total: int = 0
    retained_bytes: int = 0
    retained: int = 0
    ready: bool = False
    exited: bool = False
    versions: set[int] = field(default_factory=set)
    counts: dict[str, int] = field(default_factory=lambda: dict.fromkeys(FAMILIES, 0))
    records: list[dict] = field(default_factory=list)
    global_previous: int | None = None
    global_gaps: int = 0
    global_reordered: bool = False

    def owns_process(self, process: object) -> bool:
        """Require exact token, birth time, executable file object and image path."""
        if type(process) is not dict:
            return False
        expected = token_words(self.control.get("token"))
        if expected is None or token_words(process.get("audit_token")) != expected:
            return False
        image = self.control.get("image", {})
        executable = process.get("executable")
        if (
            type(executable) is not dict
            or executable.get("path") != self.image_path
            or executable.get("path_truncated") is not False
            or file_key(executable) != (image.get("dev"), image.get("ino"))
        ):
            return False
        try:
            stamp = datetime.fromisoformat(process["start_time"].replace("Z", "+00:00"))
            if stamp.utcoffset() is None:
                return False
            micros = int(stamp.timestamp()) * 1_000_000 + stamp.microsecond
            expected_micros = self.control["start_sec"] * 1_000_000 + self.control["start_usec"]
            return micros == expected_micros
        except (KeyError, AttributeError, TypeError, ValueError, OverflowError):
            return False

    def scratch_file(self, value: object, *, directory: bool = False) -> bool:
        """Require exact scratch paths; validate the root directory's file object."""
        if type(value) is not dict or value.get("path_truncated") is not False:
            return False
        path = value.get("path")
        if type(path) is not str:
            return False
        if directory:
            root = self.control["root"]
            return path == self.root_path and file_key(value) == (root["dev"], root["ino"])
        return (
            path in {self.root_path + "/" + name for name in NAMES} and file_key(value) is not None
        )

    def accept(self, raw: bytes) -> bool:
        """Discard unrelated rows before any native data reaches the retained file."""
        self.total += 1
        if self.total > MAX_RECORDS:
            raise RemoteReferenceError("RECORD_LIMIT")
        row = decode(raw)
        sequence = row.get("global_seq_num")
        if type(sequence) is int:
            if self.global_previous is not None:
                if sequence <= self.global_previous:
                    self.global_reordered = True
                elif sequence > self.global_previous + 1:
                    self.global_gaps += sequence - self.global_previous - 1
            self.global_previous = sequence
        if not self.owns_process(row.get("process")):
            return False
        event = row.get("event")
        if type(event) is not dict or len(event) != 1:
            raise RemoteReferenceError("OWNED_SHAPE")
        family = next(iter(event))
        if family not in FAMILIES:
            return False
        payload = event[family]
        if (
            type(payload) is not dict
            or type(row.get("version")) is not int
            or not 1 <= row["version"] <= 128
            or type(row.get("event_type")) is not int
            or row["event_type"] != EVENT_TYPES[family]
        ):
            raise RemoteReferenceError("OWNED_SHAPE")
        if type(row.get("action_type")) is not int or row["action_type"] != 1:
            raise RemoteReferenceError("OWNED_SHAPE")
        selected = False
        target = None
        if family == "exit":
            if type(payload.get("stat")) is not int:
                raise RemoteReferenceError("OWNED_SHAPE")
            selected = True
            self.exited = payload.get("stat") == 0
        elif family in {"close", "unlink"}:
            target = payload.get("target")
            selected = self.scratch_file(target)
            if selected and family == "unlink":
                selected = self.scratch_file(payload.get("parent_dir"), directory=True)
        else:
            destination = payload.get("destination")
            if type(destination) is dict:
                target = destination.get("existing_file")
                selected = self.scratch_file(target)
                new = destination.get("new_path")
                if type(new) is dict:
                    selected = (
                        self.scratch_file(new.get("dir"), directory=True)
                        and type(new.get("filename")) is str
                        and new["filename"] in NAMES
                    )
            if family == "rename":
                selected = selected and self.scratch_file(payload.get("source"))
        if not selected:
            return False
        if (
            self.retained >= MAX_RETAINED_RECORDS
            or self.retained_bytes + len(raw) + 1 > MAX_RETAINED_BYTES
        ):
            raise RemoteReferenceError("RETAINED_LIMIT")
        self.versions.add(row["version"])
        self.counts[family] += 1
        self.retained += 1
        self.retained_bytes += len(raw) + 1
        self.records.append(row)
        if (
            family == "close"
            and target.get("path") == self.root_path + "/ready"
            and payload.get("modified") is True
        ):
            self.ready = True
        return True


def private_file(path: Path) -> BinaryIO:
    """Create a new private artifact, never overwrite an earlier reference."""
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")


def stop(process: subprocess.Popen | None) -> bool:
    """Cancel owned children and allow the privileged guard to reap its collector."""
    if process is None:
        return True
    if process.poll() is None:
        if process.stdin is not None:
            process.stdin.close()
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
                return False
    return process.poll() is not None


def digest(path: Path) -> str:
    """Hash a private artifact in bounded chunks without emitting its bytes."""
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            value.update(chunk)
    return value.hexdigest()


def capture(kit: Path) -> dict:
    """Run one finite filesystem exercise on the explicitly authorized second Mac."""
    report = {
        "schema_version": 1,
        "case": "filesystem-primitives",
        "error": "NONE",
        "collector_ready": False,
        "controls_complete": False,
        "cleanup": False,
        "native_versions": [],
        "counts": dict.fromkeys(FAMILIES, 0),
        "stream_sequence_gaps": 0,
        "stream_sequence_reordered": False,
        "reference_admission": "NOT_EVALUATED",
    }
    collector = probe = None
    tracker = None
    controls: list[dict] = []
    work = None
    saved = []
    try:
        if sys.platform != "darwin" or os.getuid() == 0:
            raise RemoteReferenceError("PLATFORM")
        info = GUARD.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RemoteReferenceError("GUARD")
        work = Path(tempfile.mkdtemp(prefix="filesystem-run-", dir=kit))
        scratch = work / "scratch"
        scratch.mkdir(mode=0o700)
        executable = kit / "filesystem-probe"
        probe = subprocess.Popen(
            [str(executable)],
            cwd=scratch,
            env=SAFE_ENV,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
        assert probe.stdout is not None and probe.stdin is not None
        # The new probe emits a bounded ready record immediately and has its own
        # alarm. The parent watchdog additionally bounds this startup read.
        with selectors.DefaultSelector() as selector:
            selector.register(probe.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=3):
                raise RemoteReferenceError("PROBE")
            initial = probe.stdout.readline(4097)
        control = decode(initial)
        if control.get("kind") != "ready" or token_words(control.get("token")) is None:
            raise RemoteReferenceError("PROBE")
        controls.append(control)
        tracker = Tracker(control, str(executable), str(scratch))
        collector = subprocess.Popen(
            ["/usr/bin/sudo", "-n", str(GUARD), "filesystem"],
            env=SAFE_ENV,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        assert collector.stdout is not None and collector.stderr is not None
        started = time.monotonic()
        next_request = started
        warmups = 0
        next_step = 0
        pending_step = False
        done = False
        quiet_until = started
        buffers = {"native": b"", "control": b"", "error": b""}
        with (
            private_file(work / "native.ndjson") as output,
            selectors.DefaultSelector() as selector,
        ):
            selector.register(collector.stdout, selectors.EVENT_READ, "native")
            selector.register(collector.stderr, selectors.EVENT_READ, "error")
            selector.register(probe.stdout, selectors.EVENT_READ, "control")
            while time.monotonic() - started < 20:
                now = time.monotonic()
                if collector.poll() is not None:
                    remaining = collector.stderr.read(65537)
                    if len(remaining) <= 65536:
                        error = (buffers["error"] + remaining).lower()
                        if b"full disk access" in error or b"not permitted" in error:
                            raise RemoteReferenceError("COLLECTOR_PERMISSION")
                    raise RemoteReferenceError("COLLECTOR")
                if not tracker.ready and now >= next_request and warmups < 8:
                    probe.stdin.write(b"R")
                    probe.stdin.flush()
                    warmups += 1
                    next_request = now + 0.7
                if not tracker.ready and now - started > 8:
                    raise RemoteReferenceError("READINESS")
                if tracker.ready and not pending_step and now >= quiet_until:
                    if next_step < 8:
                        probe.stdin.write(str(next_step).encode("ascii"))
                        probe.stdin.flush()
                        pending_step = True
                    elif not done:
                        probe.stdin.write(b"Q")
                        probe.stdin.flush()
                        done = True
                for key, _mask in selector.select(timeout=0.05):
                    channel = key.data
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffers[channel] += chunk
                    if channel == "error":
                        # Retain no error text; classify only a known permission
                        # diagnostic locally and discard its buffer.
                        if len(buffers[channel]) > 65536:
                            raise RemoteReferenceError("COLLECTOR")
                        lower = buffers[channel].lower()
                        if b"full disk access" in lower or b"not permitted" in lower:
                            raise RemoteReferenceError("COLLECTOR_PERMISSION")
                        continue
                    while b"\n" in buffers[channel]:
                        raw, buffers[channel] = buffers[channel].split(b"\n", 1)
                        if not raw.strip():
                            continue
                        if channel == "native":
                            if tracker.accept(raw):
                                output.write(raw + b"\n")
                        else:
                            item = decode(raw)
                            if len(controls) >= 20:
                                raise RemoteReferenceError("CONTROL_LIMIT")
                            controls.append(item)
                            if item.get("kind") == "warmup" and item.get("ok") is not True:
                                raise RemoteReferenceError("PROBE")
                            if item.get("kind") == "step":
                                if item.get("step") != next_step or item.get("ok") is not True:
                                    raise RemoteReferenceError("PROBE")
                                next_step += 1
                                pending_step = False
                                quiet_until = time.monotonic() + 0.2
                    if len(buffers[channel]) > MAX_LINE:
                        raise RemoteReferenceError("LINE_LIMIT")
                if done and tracker.exited and probe.poll() == 0:
                    report["controls_complete"] = next_step == 8
                    break
            else:
                raise RemoteReferenceError("TIMEOUT")
            if buffers["native"].strip() or buffers["control"].strip():
                raise RemoteReferenceError("PARTIAL_LINE")
    except RemoteReferenceError as exc:
        report["error"] = str(exc)
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        report["error"] = "IO_OR_CONTROL"
    finally:
        clean_guard = stop(collector)
        clean_probe = stop(probe)
        report["cleanup"] = clean_guard and clean_probe
        for process in (collector, probe):
            if process is not None:
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()
    if tracker is not None:
        report.update(
            collector_ready=tracker.ready,
            counts=tracker.counts,
            native_versions=sorted(tracker.versions),
            stream_sequence_gaps=tracker.global_gaps,
            stream_sequence_reordered=tracker.global_reordered,
        )
    if work is not None:
        with private_file(work / "controls.json") as output:
            output.write(json.dumps(controls).encode())
        for name in ("native.ndjson", "controls.json"):
            path = work / name
            if path.exists():
                saved.append({"name": name, "sha256": digest(path)})
        with private_file(work / "provenance.json") as output:
            versions = {}
            for flag in ("-productVersion", "-buildVersion"):
                result = subprocess.run(
                    ["/usr/bin/sw_vers", flag],
                    capture_output=True,
                    timeout=3,
                    check=True,
                    env=SAFE_ENV,
                )
                versions[flag] = result.stdout.decode("ascii").strip()
            output.write(
                json.dumps(
                    {
                        "files": saved,
                        "report": report,
                        "os": versions,
                        "architecture": os.uname().machine,
                        "code": {
                            name: digest(kit / name)
                            for name in (
                                "filesystem_probe.c",
                                "filesystem-probe",
                                "filesystem_reference.py",
                            )
                        },
                        "guard_sha256": digest(GUARD),
                        "limits": {
                            "seconds": 20,
                            "input_records": MAX_RECORDS,
                            "line_bytes": MAX_LINE,
                            "retained_bytes": MAX_RETAINED_BYTES,
                            "retained_records": MAX_RETAINED_RECORDS,
                        },
                    }
                ).encode()
            )
        with private_file(work / "REPORT.json") as output:
            output.write(json.dumps(report).encode())
    return report


def main() -> None:
    """Emit only the bounded report, including when startup fails."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["capture"])
    parser.parse_args()
    signal.signal(signal.SIGTERM, lambda _number, _frame: sys.exit(2))
    signal.signal(signal.SIGHUP, lambda _number, _frame: sys.exit(2))
    try:
        report = capture(Path(__file__).resolve().parent)
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        report = {
            "schema_version": 1,
            "error": "ARTIFACT_IO",
            "reference_admission": "NOT_EVALUATED",
        }
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
