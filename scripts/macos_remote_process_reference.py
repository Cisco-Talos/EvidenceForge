# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Python 3.9+ second-host Code reference; fixed summaries and private native rows.

Use only on the explicitly authorized second Mac. Raw evidence stays in new private
run directories. This standalone stdlib boundary does not enable native generation.
Local tests use invented records and never run an installed app or native collector.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import plistlib
import re
import selectors
import subprocess
import sys
import tempfile
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType


def _support() -> ModuleType:
    path = Path(__file__).with_name("reference_support.py")
    if not path.exists():
        path = Path(__file__).with_name("macos_remote_filesystem_reference.py")
    spec = importlib.util.spec_from_file_location("_eforge_remote_process_support", path)
    if spec is None or spec.loader is None:
        raise ValueError("CODE")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


support = _support()
APP = Path("/Applications/Visual Studio Code.app")
ROLE_NAMES = ("MAIN", "RENDERER", "GPU", "NETWORK", "NODE", "UTILITY", "OTHER")
MAX_RING_BYTES = 4 * 1024 * 1024
MAX_RING_ROWS = 256
CODE_FILES = (
    "process_reference.py",
    "reference_support.py",
    "process_probe.c",
    "process-probe",
    "vscode_driver.m",
    "vscode-driver",
    "vscode_extension.js",
)


def identity(process: object) -> tuple | None:
    """Bind an execution to its full token, birth and observed image identity."""
    if type(process) is not dict:
        return None
    words = support.token_words(process.get("audit_token"))
    image = process.get("executable", {})
    key = support.file_key(image)
    birth = process.get("start_time")
    if (
        words is None
        or key is None
        or type(birth) is not str
        or type(image.get("path")) is not str
        or image.get("path_truncated") is not False
    ):
        return None
    return (
        words,
        birth,
        key,
        image["path"],
        process.get("cdhash"),
        process.get("signing_id"),
        process.get("team_id"),
    )


def lifetime(process: object) -> tuple | None:
    """Separate an immutable process birth from subsequent exec identities."""
    key = identity(process)
    return (key[0][5], key[1]) if key is not None else None


def image_matches(process: dict, image: dict) -> bool:
    """Require installed file object and signing identity, not a bundle prefix."""
    executable = process.get("executable", {})
    return (
        support.file_key(executable) == (image["dev"], image["ino"])
        and executable.get("path") in image["paths"]
        and executable.get("path_truncated") is False
        and cdhash_bytes(process.get("cdhash")) == cdhash_bytes(image["cdhash"])
        and cdhash_bytes(image["cdhash"]) is not None
        and all(process.get(name) == image[name] for name in ("signing_id", "team_id"))
    )


def cdhash_bytes(value: object) -> bytes | None:
    """Compare the signed twenty-byte value independently of hex letter case."""
    if type(value) is not str or re.fullmatch(r"[0-9a-fA-F]{40}", value) is None:
        return None
    return bytes.fromhex(value)


def option_value(arguments: list[str], name: str) -> str | None:
    """Accept one literal flag value; ambiguous options cannot authenticate a run."""
    values = []
    for index, argument in enumerate(arguments):
        if argument.startswith(name + "="):
            values.append(argument[len(name) + 1 :])
        elif argument == name and index + 1 < len(arguments):
            values.append(arguments[index + 1])
    return values[0] if len(values) == 1 else None


def role(arguments: list[str], main: bool) -> str:
    """Classify only declared Chromium/Node role switches; hide unknown values."""
    if main:
        return "MAIN"
    kind = option_value(arguments, "--type")
    if kind == "renderer":
        return "RENDERER"
    if kind == "gpu-process":
        return "GPU"
    if kind == "utility":
        subtype = option_value(arguments, "--utility-sub-type")
        return (
            "NETWORK"
            if subtype == "network.mojom.NetworkService"
            else "NODE"
            if subtype == "node.mojom.NodeService"
            else "UTILITY"
        )
    return "OTHER"


@dataclass
class Graph:
    """Retain only an authenticated main and its exact fork/exec descendants."""

    images: list[dict]
    root: str
    known: set[tuple] = field(default_factory=set)
    births: set[tuple] = field(default_factory=set)
    closed: set[tuple] = field(default_factory=set)
    main: dict | None = None
    rows: dict[int, tuple[bytes, dict]] = field(default_factory=dict)
    role_exec_counts: dict[str, int] = field(default_factory=lambda: dict.fromkeys(ROLE_NAMES, 0))
    ring: deque = field(default_factory=deque)
    ring_bytes: int = 0
    retained_bytes: int = 0
    total: int = 0
    previous_sequence: int | None = None
    sequence_gaps: int = 0
    reordered: bool = False
    unknown_images: int = 0
    ancestry_incomplete: bool = False
    authentication_checks: dict[str, int] = field(default_factory=dict)

    def diagnose_main(self, row: dict) -> None:
        """Count fixed predicates only for this run's literal isolated profile."""
        if row.get("event_type") != 9:
            return
        payload = row.get("event", {}).get("exec", {})
        target, arguments = payload.get("target", {}), payload.get("args", [])
        if type(arguments) is not list or any(type(item) is not str for item in arguments):
            return
        if option_value(arguments, "--user-data-dir") != self.root + "/profile":
            return
        image = self.images[0]
        executable = target.get("executable", {})
        checks = {
            "profile": True,
            "extensions": option_value(arguments, "--extensions-dir") == self.root + "/extensions",
            "workspace": self.root + "/workspace" in arguments,
            "file_object": support.file_key(executable) == (image["dev"], image["ino"]),
            "path": executable.get("path") in image["paths"],
            "path_complete": executable.get("path_truncated") is False,
            "cdhash": target.get("cdhash") == image["cdhash"],
            "cdhash_bytes": cdhash_bytes(target.get("cdhash")) == cdhash_bytes(image["cdhash"]),
            "signing_id": target.get("signing_id") == image["signing_id"],
            "team_id": target.get("team_id") == image["team_id"],
        }
        for name, matches in checks.items():
            self.authentication_checks[name] = self.authentication_checks.get(name, 0) + int(
                matches
            )

    def is_main(self, row: dict) -> bool:
        if row.get("event_type") != 9:
            return False
        payload = row.get("event", {}).get("exec", {})
        target, arguments = payload.get("target", {}), payload.get("args", [])
        if type(arguments) is not list or any(type(item) is not str for item in arguments):
            return False
        return (
            image_matches(target, self.images[0])
            and option_value(arguments, "--user-data-dir") == self.root + "/profile"
            and option_value(arguments, "--extensions-dir") == self.root + "/extensions"
            and self.root + "/workspace" in arguments
        )

    def retain(self, raw: bytes, row: dict) -> None:
        sequence = row["global_seq_num"]
        if sequence in self.rows:
            return
        if (
            len(self.rows) >= support.MAX_RETAINED_RECORDS
            or self.retained_bytes + len(raw) > support.MAX_RETAINED_BYTES
        ):
            raise support.RemoteReferenceError("RETAINED_LIMIT")
        self.rows[sequence] = raw, row
        self.retained_bytes += len(raw)

    def related(self, raw: bytes, row: dict) -> None:
        process = row.get("process", {})
        if identity(process) not in self.known:
            return
        kind = row.get("event_type")
        if kind == 11:
            child = row.get("event", {}).get("fork", {}).get("child")
            key = identity(child)
            if key is None:
                raise support.RemoteReferenceError("OWNED_SHAPE")
            self.known.add(key)
            self.births.add(lifetime(child))
        elif kind == 9:
            payload = row.get("event", {}).get("exec", {})
            target, arguments = payload.get("target"), payload.get("args", [])
            if (
                identity(target) is None
                or lifetime(target) != lifetime(process)
                or identity(target)[0][7] == identity(process)[0][7]
                or type(arguments) is not list
                or any(type(item) is not str for item in arguments)
            ):
                raise support.RemoteReferenceError("OWNED_SHAPE")
            if row["global_seq_num"] not in self.rows:
                self.known.add(identity(target))
                known_image = any(image_matches(target, image) for image in self.images)
                if not known_image:
                    self.unknown_images += 1
                self.role_exec_counts[role(arguments, lifetime(target) == lifetime(self.main))] += 1
        elif kind == 15:
            status = row.get("event", {}).get("exit", {}).get("stat")
            if type(status) is not int:
                raise support.RemoteReferenceError("OWNED_SHAPE")
            self.closed.add(lifetime(process))
        else:
            return
        self.retain(raw, row)

    def accept(self, raw: bytes) -> dict:
        """Process the full stream in memory; persist only proven ownership edges."""
        self.total += 1
        if self.total > support.MAX_RECORDS:
            raise support.RemoteReferenceError("RECORD_LIMIT")
        row = support.decode(raw)
        sequence = row.get("global_seq_num")
        if type(sequence) is not int or sequence < 0:
            raise support.RemoteReferenceError("STREAM_SHAPE")
        if self.previous_sequence is not None:
            if sequence <= self.previous_sequence:
                self.reordered = True
            elif sequence > self.previous_sequence + 1:
                self.sequence_gaps += sequence - self.previous_sequence - 1
        self.previous_sequence = sequence
        self.diagnose_main(row)
        self.ring.append((raw, row))
        self.ring_bytes += len(raw)
        while len(self.ring) > MAX_RING_ROWS or self.ring_bytes > MAX_RING_BYTES:
            removed, _ = self.ring.popleft()
            self.ring_bytes -= len(removed)
        if self.main is None and self.is_main(row):
            target = row["event"]["exec"]["target"]
            before = row["process"]
            if identity(target) is None or lifetime(before) != lifetime(target):
                raise support.RemoteReferenceError("MAIN_SHAPE")
            self.main = target
            self.known.update((identity(target), identity(before)))
            self.role_exec_counts["MAIN"] += 1
            self.retain(raw, row)
            # Exact pre-exec snapshots may also bind an earlier fork/exec in the
            # finite ring. Missing ancestry remains explicit; no PID fallback.
            ancestors = {identity(before)}
            for _ in range(3):
                for old_raw, old in self.ring:
                    child = old.get("event", {}).get("fork", {}).get("child")
                    post = old.get("event", {}).get("exec", {}).get("target")
                    if identity(child) in ancestors or identity(post) in ancestors:
                        if identity(old.get("process")) is not None:
                            # An ancestor is proof for this exact edge, never a
                            # descendant-dispatch owner: launchd's other children
                            # are unrelated to the controlled Code instance.
                            ancestors.add(identity(old["process"]))
                            if child is not None:
                                self.births.add(lifetime(child))
                            self.retain(old_raw, old)
        if self.main is not None:
            self.related(raw, row)
        return row


def command(arguments: list[str]) -> subprocess.CompletedProcess:
    """Capture installed-code diagnostics privately, with a fixed timeout/bound."""
    result = subprocess.run(
        arguments, stdin=subprocess.DEVNULL, capture_output=True, env=support.SAFE_ENV, timeout=15
    )
    if result.returncode or len(result.stdout) + len(result.stderr) > support.MAX_LINE:
        raise support.RemoteReferenceError("INSTALLED_CODE")
    return result


def installed_images() -> list[dict]:
    """Pin only the selected Code main/helpers and their exact signed file objects."""
    info = plistlib.loads((APP / "Contents/Info.plist").read_bytes())
    if info.get("CFBundleExecutable") != "Code":
        raise support.RemoteReferenceError("INSTALLED_CODE")
    if (
        Path("/Applications/code-portable-data").exists()
        or (APP / "Contents/Resources/app/data").exists()
    ):
        raise support.RemoteReferenceError("PORTABLE_MODE")
    targets = [(APP, APP / "Contents/MacOS/Code")]
    for name in (
        "Code Helper",
        "Code Helper (GPU)",
        "Code Helper (Plugin)",
        "Code Helper (Renderer)",
    ):
        bundle = APP / "Contents/Frameworks" / (name + ".app")
        targets.append((bundle, bundle / "Contents/MacOS" / name))
    crashpad = (
        APP / "Contents/Frameworks/Electron Framework.framework/Helpers/chrome_crashpad_handler"
    )
    if crashpad.is_file():
        targets.append((crashpad, crashpad))
    images = []
    for bundle, path in targets:
        command(
            [
                "/usr/bin/codesign",
                "--verify",
                "-R",
                '=anchor apple generic and certificate leaf[subject.OU] = "UBF8T346G9"',
                str(bundle),
            ]
        )
        display = command(["/usr/bin/codesign", "-dv", "--arch", "arm64", "--verbose=4", str(path)])
        metadata = {}
        for line in display.stderr.decode("utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator and key in {"Identifier", "TeamIdentifier", "CDHash"}:
                if key in metadata:
                    raise support.RemoteReferenceError("INSTALLED_CODE")
                metadata[key] = value
        attributes = path.stat()
        images.append(
            {
                "paths": sorted({str(path), str(path.resolve())}),
                "dev": attributes.st_dev,
                "ino": attributes.st_ino,
                "sha256": support.digest(path),
                "signing_id": metadata["Identifier"],
                "team_id": metadata["TeamIdentifier"],
                "cdhash": metadata["CDHash"].lower(),
                "version": info["CFBundleShortVersionString"],
            }
        )
    return images


def prepare_workspace(work: Path, kit: Path) -> None:
    """Install only our harmless extension in this run's fresh profile/workspace."""
    for name in ("workspace", "second-workspace", "extensions", "profile", "shell"):
        (work / name).mkdir(mode=0o700)
    user = work / "profile/User"
    user.mkdir(mode=0o700)
    (user / "settings.json").write_text(
        json.dumps(
            {
                "update.mode": "none",
                "extensions.autoUpdate": False,
                "extensions.autoCheckUpdates": False,
                "telemetry.telemetryLevel": "off",
                "workbench.startupEditor": "none",
                "window.confirmBeforeClose": "never",
                "git.enabled": False,
                "extensions.ignoreRecommendations": True,
            }
        )
    )
    (work / "workspace/example.txt").write_text("before\n")
    extension = work / "extensions/evidenceforge.native-reference-0.0.1"
    extension.mkdir(mode=0o700)
    (extension / "package.json").write_text(
        json.dumps(
            {
                "name": "native-reference",
                "publisher": "evidenceforge",
                "version": "0.0.1",
                "engines": {"vscode": "^1.80.0"},
                "main": "./extension.js",
                "activationEvents": ["onStartupFinished"],
                "capabilities": {"untrustedWorkspaces": {"supported": True}},
            }
        )
    )
    (extension / "extension.js").write_bytes((kit / "vscode_extension.js").read_bytes())
    (extension / "reference.json").write_text(
        json.dumps({"root": str(work), "nonce": uuid.uuid4().hex})
    )


def capture(kit: Path) -> dict:
    """Run one controlled Code lifecycle; keep all native and launch facts private."""
    os.umask(0o077)
    result = {
        "schema_version": 1,
        "case": "vscode",
        "error": "NONE",
        "collector_ready": False,
        "app_launch_control": False,
        "save_control": False,
        "second_window_control": False,
        "ordinary_quit": False,
        "cleanup": False,
        "reference_admission": "NOT_EVALUATED",
    }
    probe = collector = driver = None
    graph = None
    work = None
    controls = []
    provenance = {}
    try:
        images = installed_images()
        work = Path(tempfile.mkdtemp(prefix="vscode-run-", dir=kit))
        code = work / "code"
        code.mkdir(mode=0o700)
        for name in CODE_FILES:
            with support.private_file(code / name) as output:
                output.write((kit / name).read_bytes())
        provenance = {
            "architecture": platform.machine(),
            "os_version": command(["/usr/bin/sw_vers", "-productVersion"]).stdout.decode().strip(),
            "os_build": command(["/usr/bin/sw_vers", "-buildVersion"]).stdout.decode().strip(),
            "code_sha256": {item.name: support.digest(item) for item in code.iterdir()},
            "guard_sha256": support.digest(support.GUARD),
        }
        prepare_workspace(work, kit)
        graph = Graph(images, str(work))
        probe = subprocess.Popen(
            [str(kit / "process-probe")],
            cwd=work,
            env=support.SAFE_ENV,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
        assert probe.stdout is not None and probe.stdin is not None
        with selectors.DefaultSelector() as selector:
            selector.register(probe.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=3):
                raise support.RemoteReferenceError("PROBE")
            ready = support.decode(probe.stdout.readline(4097))
        if ready.get("kind") != "ready":
            raise support.RemoteReferenceError("PROBE")
        readiness = support.Tracker(ready, str(kit / "process-probe"), str(work))
        controls.append(ready)
        collector = subprocess.Popen(
            ["/usr/bin/sudo", "-n", str(support.GUARD), "process"],
            env=support.SAFE_ENV,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
        assert collector.stdout is not None
        started = time.monotonic()
        next_warmup = started
        warmups = 0
        buffers = {"native": b"", "driver": b""}
        quiet = None
        with selectors.DefaultSelector() as selector:
            selector.register(collector.stdout, selectors.EVENT_READ, "native")
            while time.monotonic() - started < 90:
                now = time.monotonic()
                if collector.poll() is not None:
                    raise support.RemoteReferenceError("COLLECTOR")
                if not result["collector_ready"] and now >= next_warmup and warmups < 8:
                    probe.stdin.write(b"R")
                    probe.stdin.flush()
                    warmups += 1
                    next_warmup = now + 0.7
                if not result["collector_ready"] and now - started > 8:
                    raise support.RemoteReferenceError("READINESS")
                if result["collector_ready"] and driver is None:
                    driver = subprocess.Popen(
                        [str(kit / "vscode-driver"), str(work)],
                        cwd=work,
                        env=support.SAFE_ENV,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        bufsize=0,
                    )
                    selector.register(driver.stdout, selectors.EVENT_READ, "driver")
                for key, _mask in selector.select(timeout=0.05):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    channel = key.data
                    buffers[channel] += chunk
                    while b"\n" in buffers[channel]:
                        raw, buffers[channel] = buffers[channel].split(b"\n", 1)
                        if not raw.strip():
                            continue
                        if channel == "driver":
                            item = support.decode(raw)
                            if len(controls) > 8:
                                raise support.RemoteReferenceError("CONTROL_LIMIT")
                            controls.append(item)
                            if item.get("kind") == "launch":
                                result["app_launch_control"] = item.get("ok") is True
                        else:
                            row = graph.accept(raw)
                            if row.get("event_type") == 11 and readiness.owns_process(
                                row.get("process")
                            ):
                                result["collector_ready"] = True
                    if len(buffers[channel]) > support.MAX_LINE:
                        raise support.RemoteReferenceError("LINE_LIMIT")
                if driver is not None and driver.poll() is not None:
                    if quiet is None:
                        quiet = time.monotonic() + 1.0
                    if time.monotonic() >= quiet:
                        break
            else:
                raise support.RemoteReferenceError("TIMEOUT")
        nonce = json.loads(
            (work / "extensions/evidenceforge.native-reference-0.0.1/reference.json").read_text()
        )["nonce"]
        workflow = support.decode((work / "workflow-control.json").read_bytes())
        second = support.decode((work / "second-window.json").read_bytes())
        if workflow.get("nonce") != nonce or second.get("nonce") != nonce:
            raise support.RemoteReferenceError("WORKFLOW_CONTROL")
        result["save_control"] = (
            workflow.get("saved") is True
            and (work / "workspace/example.txt").read_text() == "reference save complete\n"
        )
        result["second_window_control"] = (
            workflow.get("second") is True and second.get("ready") is True
        )
        result["ordinary_quit"] = any(
            item.get("kind") == "ended"
            and item.get("terminated") is True
            and item.get("forced") is False
            for item in controls
        )
        result["installed_code_unchanged"] = all(
            support.digest(Path(image["paths"][0])) == image["sha256"] for image in images
        )
    except support.RemoteReferenceError as exc:
        result["error"] = str(exc)
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        result["error"] = "IO_OR_CONTROL"
    finally:
        clean_driver = True
        if driver is not None:
            if driver.stdin is not None and not driver.stdin.closed:
                driver.stdin.close()
            try:
                driver.wait(timeout=10)
                clean_driver = driver.returncode == 0
            except subprocess.TimeoutExpired:
                clean_driver = False
        clean_collector = support.stop(collector)
        clean_probe = support.stop(probe)
        result["cleanup"] = clean_collector and clean_probe and clean_driver
        for process in (driver, collector, probe):
            if process is not None:
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()
    if graph is not None:
        result.update(
            main_observed=graph.main is not None,
            main_birth_observed=graph.main is not None and lifetime(graph.main) in graph.births,
            main_exit_observed=graph.main is not None and lifetime(graph.main) in graph.closed,
            role_exec_counts=graph.role_exec_counts,
            fork_births=len(graph.births),
            closed_lifetimes=len(graph.closed),
            open_lifetimes=len(graph.births - graph.closed),
            unknown_image_execs=graph.unknown_images,
            stream_sequence_gaps=graph.sequence_gaps,
            stream_sequence_reordered=graph.reordered,
            authentication_checks=graph.authentication_checks,
        )
    if work is not None:
        with support.private_file(work / "native.ndjson") as output:
            for sequence in sorted(graph.rows):
                output.write(graph.rows[sequence][0] + b"\n")
        with support.private_file(work / "controls.json") as output:
            output.write(json.dumps(controls).encode())
        with support.private_file(work / "manifest.json") as output:
            output.write(
                json.dumps(
                    {
                        "images": graph.images,
                        "root": str(work),
                        "report": result,
                        "native_sha256": support.digest(work / "native.ndjson"),
                        "controls_sha256": support.digest(work / "controls.json"),
                        "provenance": provenance,
                    }
                ).encode()
            )
        with support.private_file(work / "REPORT.json") as output:
            output.write(json.dumps(result).encode())
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["capture"])
    parser.parse_args()
    try:
        report = capture(Path(__file__).resolve().parent)
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        report = {"error": "ARTIFACT_IO", "reference_admission": "NOT_EVALUATED"}
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
