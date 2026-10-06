"""Start the local helper independently of the native window's lifetime."""

from __future__ import annotations

import hashlib
import os
import plistlib
import re
import subprocess
import sys

import psutil

from evidenceforge.studio.paths import StudioPaths
from evidenceforge.studio.runtime import command_environment, runtime_root
from evidenceforge.studio.state_io import atomic_write, open_regular


def _macos_environment() -> dict[str, str]:
    """Forward runtime locations without persisting unrelated shell credentials."""
    names = {"HOME", "PATH", "TMPDIR", "LANG", "LC_ALL", "PYTHONPATH", "CODEX_HOME"}
    environment = {
        key: value
        for key, value in command_environment().items()
        if key in names or key.startswith(("EFORGE_", "XDG_"))
    }
    environment["EFORGE_STUDIO_DAEMON"] = "1"
    return environment


def macos_service_label(paths: StudioPaths) -> str:
    """Identify this data directory's transient launchd service."""
    digest = hashlib.sha256(os.fsencode(paths.state.resolve())).hexdigest()[:24]
    return f"org.evidenceforge.studio.service.{digest}"


def _start_macos(paths: StudioPaths) -> None:
    """Use launchd so macOS does not attribute an orphan helper to the closed app."""
    label = macos_service_label(paths)
    domain = f"gui/{os.getuid()}"
    target = f"{domain}/{label}"
    log = str(paths.logs / "service.log")
    configuration: dict[str, object] = {
        "Label": label,
        "ProgramArguments": [
            sys.executable,
            *(["-I", "-B"] if runtime_root() is not None else []),
            "-m",
            "evidenceforge.studio.bootstrap",
            "--serve",
        ],
        "EnvironmentVariables": _macos_environment(),
        "RunAtLoad": True,
        "StandardOutPath": log,
        "StandardErrorPath": log,
    }
    agent = paths.state / "service-agent.plist"
    atomic_write(agent, plistlib.dumps(configuration))
    existing = subprocess.run(
        ["/bin/launchctl", "print", target],
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )
    if existing.returncode == 0:
        # A loaded but exited launchd service retains its old ProgramArguments.
        # Re-register it so relocation/upgrades use the selected retained runtime.
        match = re.search(r"\bpid = (\d+)", existing.stdout or "")
        if match and psutil.pid_exists(int(match[1])):
            raise RuntimeError(
                "Studio's launchd helper is still running without a usable descriptor"
            )
        retired = subprocess.run(
            ["/bin/launchctl", "bootout", target], capture_output=True, check=False, timeout=5
        )
        if retired.returncode != 0:
            raise RuntimeError("Could not retire Studio's exited launchd registration")
    command = ["/bin/launchctl", "bootstrap", domain, str(agent)]
    result = subprocess.run(command, capture_output=True, check=False, timeout=5)
    if result.returncode != 0:
        raise RuntimeError(
            f"Could not start Studio's launchd helper (exit {result.returncode}); "
            f"see {paths.logs / 'service.log'}"
        )


def start_background_service(paths: StudioPaths) -> None:
    """Start a detached helper, using a transient user launch agent on macOS."""
    from evidenceforge.studio.ownership import validate_private_paths

    validate_private_paths(paths)
    if sys.platform == "darwin":
        _start_macos(paths)
        return
    from evidenceforge.studio.ownership import secure_directory

    secure_directory(paths.logs, repair=True)
    with os.fdopen(
        open_regular(paths.logs / "service.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND), "ab"
    ) as log:
        subprocess.Popen(
            [sys.executable, "-m", "evidenceforge.studio.bootstrap", "--serve"],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env={**os.environ, "EFORGE_STUDIO_DAEMON": "1"},
        )
