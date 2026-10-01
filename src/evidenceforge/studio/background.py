"""Start the local helper independently of the native window's lifetime."""

from __future__ import annotations

import hashlib
import os
import plistlib
import subprocess
import sys

from evidenceforge.studio.paths import StudioPaths


def _macos_environment() -> dict[str, str]:
    """Forward runtime locations without persisting unrelated shell credentials."""
    names = {"HOME", "PATH", "TMPDIR", "LANG", "LC_ALL", "PYTHONPATH", "CODEX_HOME"}
    environment = {
        key: value
        for key, value in os.environ.items()
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
        "ProgramArguments": [sys.executable, "-m", "evidenceforge.studio.bootstrap", "--serve"],
        "EnvironmentVariables": _macos_environment(),
        "RunAtLoad": True,
        "StandardOutPath": log,
        "StandardErrorPath": log,
    }
    agent = paths.state / "service-agent.plist"
    temporary = agent.with_suffix(f".{os.getpid()}.tmp")
    try:
        with os.fdopen(
            os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb"
        ) as out:
            plistlib.dump(configuration, out)
        os.replace(temporary, agent)
    finally:
        temporary.unlink(missing_ok=True)
    existing = subprocess.run(
        ["/bin/launchctl", "print", target], capture_output=True, check=False, timeout=5
    )
    command = (
        ["/bin/launchctl", "kickstart", target]
        if existing.returncode == 0
        else ["/bin/launchctl", "bootstrap", domain, str(agent)]
    )
    result = subprocess.run(command, capture_output=True, check=False, timeout=5)
    if result.returncode != 0:
        raise RuntimeError(
            f"Could not start Studio's launchd helper (exit {result.returncode}); "
            f"see {paths.logs / 'service.log'}"
        )


def start_background_service(paths: StudioPaths) -> None:
    """Start a detached helper, using a transient user launch agent on macOS."""
    if sys.platform == "darwin":
        _start_macos(paths)
        return
    with (paths.logs / "service.log").open("ab") as log:
        subprocess.Popen(
            [sys.executable, "-m", "evidenceforge.studio.bootstrap", "--serve"],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env={**os.environ, "EFORGE_STUDIO_DAEMON": "1"},
        )
