# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded second-host Docker startup/readiness/quit reference (Python 3.9+).

Uses a fresh CLI config and an explicit local socket. Never reads login config,
pulls images, creates containers, force-stops Docker, or persists ambient rows.
Raw owned evidence stays private on the authorized second Mac.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import plistlib
import pwd
import selectors
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType


def graph_module() -> ModuleType:
    """Load the reviewed exact-execution graph from a co-located source file."""
    root = Path(__file__).resolve().parent
    path = root / "process_reference.py"
    if not path.exists():
        path = root / "macos_remote_process_reference.py"
    spec = importlib.util.spec_from_file_location("_eforge_docker_graph", path)
    if spec is None or spec.loader is None:
        raise ValueError("CODE")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


process = graph_module()
support = process.support
APP = Path("/Applications/Docker.app")
CLI = APP / "Contents/Resources/bin/docker"
CODE_FILES = (
    "docker_reference.py",
    "process_reference.py",
    "reference_support.py",
    "process_probe.c",
    "process-probe",
    "vscode_driver.m",
    "docker-driver",
    "docker_images.json",
)


@dataclass
class DockerGraph(process.Graph):
    """Authenticate a fresh signed backend by an exact injected run marker."""

    def is_main(self, row: dict) -> bool:
        if row.get("event_type") != 9:
            return False
        payload = row.get("event", {}).get("exec", {})
        environment = payload.get("env")
        return (
            type(environment) is list
            and all(type(item) is str for item in environment)
            and environment.count("EFORGE_REFERENCE_RUN=" + self.root) == 1
            and process.image_matches(payload.get("target", {}), self.images[0])
        )


def installed_images(kit: Path) -> list[dict]:
    """Pin only public selected Docker images to exact signed file objects."""
    info = plistlib.loads((APP / "Contents/Info.plist").read_bytes())
    if info.get("CFBundleExecutable") != "com.docker.backend":
        raise support.RemoteReferenceError("INSTALLED_CODE")
    process.command(
        [
            "/usr/bin/codesign",
            "--verify",
            "-R",
            '=anchor apple generic and certificate leaf[subject.OU] = "9BNSXJN65R"',
            str(APP),
        ]
    )
    candidates = json.loads((kit / "docker_images.json").read_bytes())
    images = []
    for label, relative in candidates:
        path = APP / relative
        if not path.is_file():
            continue
        process.command(
            [
                "/usr/bin/codesign",
                "--verify",
                "-R",
                '=anchor apple generic and certificate leaf[subject.OU] = "9BNSXJN65R"',
                str(path),
            ]
        )
        display = process.command(
            [
                "/usr/bin/codesign",
                "-dv",
                "--arch",
                "arm64",
                "--verbose=4",
                str(path),
            ]
        )
        metadata = {}
        for line in display.stderr.decode().splitlines():
            key, separator, value = line.partition("=")
            if separator and key in {"Identifier", "TeamIdentifier", "CDHash"}:
                if key in metadata:
                    raise support.RemoteReferenceError("INSTALLED_CODE")
                metadata[key] = value
        attributes = path.stat()
        images.append(
            {
                "role": label,
                "paths": sorted({str(path), str(path.resolve())}),
                "dev": attributes.st_dev,
                "ino": attributes.st_ino,
                "sha256": support.digest(path),
                "cdhash": metadata["CDHash"].lower(),
                "signing_id": metadata["Identifier"],
                "team_id": metadata["TeamIdentifier"],
                "version": info["CFBundleShortVersionString"],
                "build": info["CFBundleVersion"],
            }
        )
    if not images or images[0]["role"] != "BACKEND":
        raise support.RemoteReferenceError("INSTALLED_CODE")
    return images


def cli_arguments(work: Path) -> list[str]:
    """Select the known local Desktop socket, independently of active contexts."""
    socket = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".docker/run/docker.sock"
    return [str(CLI), "--host", "unix://" + str(socket), "--config", str(work / "cli-config")]


def cli(work: Path, args: list[str], timeout: int = 10) -> bytes:
    """Consume only bounded command controls, suppressing private diagnostics."""
    completed = subprocess.run(
        cli_arguments(work) + args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=timeout,
        env=support.SAFE_ENV,
    )
    if completed.returncode or len(completed.stdout) > 65536:
        raise support.RemoteReferenceError("CLI_CONTROL")
    return completed.stdout


def inventory_empty(raw: bytes) -> bool:
    """No existing container is safe to restart for this experiment."""
    if len(raw) > 65536:
        raise support.RemoteReferenceError("CLI_CONTROL")
    return not raw.strip()


def engine_ready(work: Path) -> bool:
    """Use the explicit local Engine API rather than isolated Desktop CLI state."""
    completed = subprocess.run(
        cli_arguments(work) + ["version", "--format", "{{json .Server}}"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=10,
        env=support.SAFE_ENV,
    )
    if completed.returncode:
        return False
    value = support.decode(completed.stdout)
    return value.get("Os") == "linux" and value.get("Arch") == "arm64"


def wait_engine(work: Path, expected: bool, seconds: int) -> bool:
    """Bound confirmation independently of application launch/quit callbacks."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if engine_ready(work) is expected:
            return True
        time.sleep(0.25)
    return False


def run_stream(work: Path, kit: Path, graph: DockerGraph, result: dict, controls: list) -> None:
    """Capture one finite lifecycle and stop only after an empty-container control."""
    probe = collector = driver = job = None
    try:
        probe = subprocess.Popen(
            [str(kit / "process-probe")],
            cwd=work,
            env=support.SAFE_ENV,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
        with selectors.DefaultSelector() as selector:
            selector.register(probe.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=3):
                raise support.RemoteReferenceError("PROBE")
            ready = support.decode(probe.stdout.readline(4097))
        controls.append(ready)
        readiness = support.Tracker(ready, str(kit / "process-probe"), str(work))
        collector = subprocess.Popen(
            ["/usr/bin/sudo", "-n", str(support.GUARD), "process"],
            env=support.SAFE_ENV,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
        started = time.monotonic()
        next_warmup, warmups = started, 0
        next_job = started
        job_name = ""
        phase = "version"
        quiet_until = None
        buffers = {"native": b"", "driver": b"", "cli": b""}
        with selectors.DefaultSelector() as selector:
            selector.register(collector.stdout, selectors.EVENT_READ, "native")
            while time.monotonic() - started < 150:
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
                        [str(kit / "docker-driver"), str(work)],
                        cwd=work,
                        env=support.SAFE_ENV,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        bufsize=0,
                    )
                    selector.register(driver.stdout, selectors.EVENT_READ, "driver")
                if driver is not None and job is None and now >= next_job and phase != "done":
                    job_name = phase
                    args = {
                        "version": ["version", "--format", "{{json .Server}}"],
                        "inventory": ["ps", "--all", "--quiet"],
                        "stopped": ["version", "--format", "{{json .Server}}"],
                    }[phase]
                    job = subprocess.Popen(
                        cli_arguments(work) + args,
                        env=support.SAFE_ENV,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        bufsize=0,
                    )
                    buffers["cli"] = b""
                    job_started = now
                    selector.register(job.stdout, selectors.EVENT_READ, "cli")
                for key, _ in selector.select(timeout=0.05):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    channel = key.data
                    buffers[channel] += chunk
                    if len(buffers[channel]) > support.MAX_LINE:
                        raise support.RemoteReferenceError("LINE_LIMIT")
                    if channel == "cli":
                        continue
                    while b"\n" in buffers[channel]:
                        raw, buffers[channel] = buffers[channel].split(b"\n", 1)
                        if not raw.strip():
                            continue
                        if channel == "native":
                            row = graph.accept(raw)
                            if row.get("event_type") == 11 and readiness.owns_process(
                                row.get("process")
                            ):
                                result["collector_ready"] = True
                        else:
                            item = support.decode(raw)
                            if len(controls) >= 10:
                                raise support.RemoteReferenceError("CONTROL_LIMIT")
                            controls.append(item)
                            if item.get("kind") == "launch":
                                result["app_launch_control"] = item.get("ok") is True
                            elif item.get("kind") == "quit_request":
                                result["ordinary_quit_request"] = item.get("accepted") is True
                if job is not None:
                    if now - job_started > 10:
                        raise support.RemoteReferenceError("CLI_TIMEOUT")
                    # Wait for both process completion and stdout EOF; no partial
                    # JSON or incomplete container inventory may become a control.
                    if job.poll() is not None and job.stdout not in selector.get_map():
                        raw = buffers["cli"]
                        succeeded = job.returncode == 0
                        job.stdout.close()
                        job = None
                        next_job = now + 1
                        if job_name == "version":
                            if succeeded:
                                server = support.decode(raw)
                                if server.get("Os") != "linux" or server.get("Arch") != "arm64":
                                    raise support.RemoteReferenceError("ENGINE_TARGET")
                                result["engine_ready_control"] = True
                                controls.append({"kind": "engine", "server": server})
                                phase = "inventory"
                            elif now - started > 75:
                                raise support.RemoteReferenceError("ENGINE_READINESS")
                        elif job_name == "inventory":
                            if not succeeded:
                                raise support.RemoteReferenceError("CLI_CONTROL")
                            if not inventory_empty(raw):
                                raise support.RemoteReferenceError("EXISTING_CONTAINERS")
                            result["empty_before_quit"] = True
                            driver.stdin.write(b"Q")
                            driver.stdin.flush()
                            phase = "stopped"
                            quit_started = now
                        else:
                            if not succeeded and driver.poll() == 0:
                                result["stopped_control"] = True
                                phase = "done"
                                quiet_until = now + 8
                            elif now - quit_started > 35:
                                raise support.RemoteReferenceError("ORDINARY_QUIT")
                if quiet_until is not None and now >= quiet_until and driver.poll() is not None:
                    break
            else:
                raise support.RemoteReferenceError("TIMEOUT")
    finally:
        clean_job = support.stop(job)
        # Docker driver EOF detaches; only an explicit Q requests ordinary quit.
        clean_driver = support.stop(driver)
        clean_collector = support.stop(collector)
        clean_probe = support.stop(probe)
        result["cleanup"] = clean_job and clean_driver and clean_collector and clean_probe
        for child in (job, driver, collector, probe):
            if child is not None:
                for stream in (child.stdin, child.stdout, child.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()


def capture(kit: Path) -> dict:
    """Run one private lifecycle, restoring Docker's original running state."""
    os.umask(0o077)
    work = Path(tempfile.mkdtemp(prefix="docker-run-", dir=kit))
    result = dict.fromkeys(
        (
            "collector_ready",
            "app_launch_control",
            "engine_ready_control",
            "empty_before_quit",
            "ordinary_quit_request",
            "stopped_control",
            "cleanup",
            "original_running_restored",
        ),
        False,
    )
    result.update(
        schema_version=1,
        case="docker-start-readiness-quit",
        error="NONE",
        reference_admission="NOT_EVALUATED",
        capture_started=False,
    )
    result["cleanup"] = True
    images, controls, provenance = [], [], {}
    graph = None
    original_running = False
    try:
        (work / "shell").mkdir(mode=0o700)
        (work / "cli-config").mkdir(mode=0o700)
        (work / "cli-config/config.json").write_text(
            json.dumps(
                {
                    "cliPluginsExtraDirs": [str(APP / "Contents/Resources/cli-plugins")],
                }
            )
        )
        code = work / "code"
        code.mkdir(mode=0o700)
        for name in CODE_FILES:
            with support.private_file(code / name) as output:
                output.write((kit / name).read_bytes())
        images = installed_images(kit)
        graph = DockerGraph(images, str(work))
        provenance = {
            "architecture": platform.machine(),
            "os_version": process.command(["/usr/bin/sw_vers", "-productVersion"])
            .stdout.decode()
            .strip(),
            "os_build": process.command(["/usr/bin/sw_vers", "-buildVersion"])
            .stdout.decode()
            .strip(),
            "code_sha256": {name: support.digest(code / name) for name in CODE_FILES},
            "guard_sha256": support.digest(support.GUARD),
            "driver_defines": ["EFORGE_DOCKER_REFERENCE"],
            "probe_defines": ["EFORGE_PROCESS_PROBE_LIMIT=170"],
        }
        original_running = engine_ready(work)
        if not original_running:
            raise support.RemoteReferenceError("INITIAL_DESKTOP_NOT_RUNNING")
        if not inventory_empty(cli(work, ["ps", "--all", "--quiet"])):
            raise support.RemoteReferenceError("EXISTING_CONTAINERS")
        initial = subprocess.run(
            [str(kit / "docker-driver"), "--quit-existing"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=35,
            env=support.SAFE_ENV,
        )
        with support.private_file(work / "initial-controls.ndjson") as output:
            output.write(initial.stdout[:4097])
        if initial.returncode or len(initial.stdout) > 4096 or not wait_engine(work, False, 30):
            raise support.RemoteReferenceError("INITIAL_STOP")
        result["initial_stopped_control"] = True
        result["capture_started"] = True
        run_stream(work, kit, graph, result, controls)
        if not result["app_launch_control"]:
            raise support.RemoteReferenceError("APP_LAUNCH")
        if graph.main is None:
            raise support.RemoteReferenceError("MAIN_NOT_AUTHENTICATED")
        result["installed_code_unchanged"] = all(
            support.digest(Path(image["paths"][0])) == image["sha256"] for image in images
        )
    except support.RemoteReferenceError as exc:
        result["error"] = str(exc)
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        result["error"] = "IO_OR_CONTROL"
    finally:
        if original_running:
            try:
                if not engine_ready(work):
                    subprocess.run(
                        [str(kit / "docker-driver"), str(work), "--start-only"],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=15,
                        env=support.SAFE_ENV,
                        check=False,
                    )
                result["original_running_restored"] = wait_engine(work, True, 60)
            except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
                result["original_running_restored"] = False
    if graph is not None:
        main_life = process.lifetime(graph.main)
        counts = dict.fromkeys([image["role"] for image in images] + ["UNKNOWN"], 0)
        for _, row in graph.rows.values():
            if row.get("event_type") == 9:
                target = row["event"]["exec"]["target"]
                label = next(
                    (image["role"] for image in images if process.image_matches(target, image)),
                    "UNKNOWN",
                )
                counts[label] += 1
        result.update(
            main_observed=graph.main is not None,
            main_birth_observed=main_life in graph.births,
            main_exit_observed=main_life in graph.closed,
            selected_image_exec_counts=counts,
            fork_births=len(graph.births),
            closed_lifetimes=len(graph.closed),
            open_lifetimes=len(
                (graph.births | ({main_life} if main_life else set())) - graph.closed
            ),
            stream_sequence_gaps=graph.sequence_gaps,
            stream_sequence_reordered=graph.reordered,
        )
    with support.private_file(work / "native.ndjson") as output:
        if graph is not None:
            for sequence in sorted(graph.rows):
                output.write(graph.rows[sequence][0] + b"\n")
    with support.private_file(work / "controls.json") as output:
        output.write(json.dumps(controls).encode())
    with support.private_file(work / "REPORT.json") as output:
        output.write(json.dumps(result).encode())
    with support.private_file(work / "manifest.json") as output:
        output.write(
            json.dumps(
                {
                    "images": images,
                    "root": str(work),
                    "report": result,
                    "provenance": provenance,
                    "native_sha256": support.digest(work / "native.ndjson"),
                    "controls_sha256": support.digest(work / "controls.json"),
                }
            ).encode()
        )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["capture"])
    parser.parse_args()
    try:
        result = capture(Path(__file__).resolve().parent)
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        result = {"error": "ARTIFACT_IO", "reference_admission": "NOT_EVALUATED"}
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
