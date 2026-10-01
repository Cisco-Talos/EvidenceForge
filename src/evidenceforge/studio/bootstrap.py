"""Attach to or start the one local EvidenceForge Studio service."""

from __future__ import annotations

import json
import os
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import psutil
import uvicorn
from pydantic import BaseModel, ConfigDict

if os.name == "posix":
    import fcntl

from evidenceforge.studio.paths import StudioPaths, studio_paths
from evidenceforge.studio.service import create_app


class ServiceDescriptor(BaseModel):
    """Private capability required to connect to the loopback service."""

    model_config = ConfigDict(extra="forbid")

    pid: int
    created_at: float
    port: int
    token: str

    @property
    def url(self) -> str:
        """Return the API origin for the desktop renderer."""
        return f"http://127.0.0.1:{self.port}"


def _read_descriptor(path: Path) -> ServiceDescriptor | None:
    try:
        return ServiceDescriptor.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _is_live(descriptor: ServiceDescriptor) -> bool:
    try:
        process = psutil.Process(descriptor.pid)
        if abs(process.create_time() - descriptor.created_at) >= 0.01:
            return False
        request = urllib.request.Request(
            f"{descriptor.url}/v1/health",
            headers={"X-EForge-Token": descriptor.token},
        )
        with urllib.request.urlopen(request, timeout=0.35) as response:
            return response.status == 200
    except (OSError, psutil.Error, urllib.error.URLError, TimeoutError):
        return False


def connect_or_start(paths: StudioPaths | None = None) -> ServiceDescriptor:
    """Return the existing service or launch a detached one and await readiness."""
    app_paths = paths or studio_paths()
    app_paths.state.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = app_paths.state / "service-start.lock"
    with lock_path.open("a+") as lock:
        if os.name == "posix":
            fcntl.flock(lock, fcntl.LOCK_EX)
        descriptor = _read_descriptor(app_paths.service_file)
        if descriptor and _is_live(descriptor):
            return descriptor
        app_paths.logs.mkdir(parents=True, exist_ok=True)
        with (app_paths.logs / "service.log").open("ab") as log:
            subprocess.Popen(
                [sys.executable, "-m", "evidenceforge.studio.bootstrap", "--serve"],
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                env={**os.environ, "EFORGE_STUDIO_DAEMON": "1"},
            )
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            descriptor = _read_descriptor(app_paths.service_file)
            if descriptor and _is_live(descriptor):
                return descriptor
            time.sleep(0.1)
    raise RuntimeError(f"Studio service did not become ready; see {app_paths.logs / 'service.log'}")


def serve(paths: StudioPaths | None = None) -> None:
    """Bind a private loopback socket and run the background service."""
    app_paths = paths or studio_paths()
    app_paths.state.mkdir(parents=True, exist_ok=True, mode=0o700)
    existing = _read_descriptor(app_paths.service_file)
    if existing and _is_live(existing):
        return
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    descriptor = ServiceDescriptor(
        pid=os.getpid(),
        created_at=psutil.Process().create_time(),
        port=int(listener.getsockname()[1]),
        token=secrets.token_urlsafe(32),
    )
    temporary = app_paths.service_file.with_suffix(f".{os.getpid()}.tmp")
    with os.fdopen(os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as out:
        out.write(descriptor.model_dump_json())
    os.replace(temporary, app_paths.service_file)
    try:
        app = create_app(app_paths, descriptor.token)
        config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=descriptor.port,
            log_level="warning",
            timeout_graceful_shutdown=3,
        )
        server = uvicorn.Server(config)
        import asyncio

        asyncio.run(server.serve(sockets=[listener]))
    finally:
        current = _read_descriptor(app_paths.service_file)
        if current and current.pid == os.getpid():
            app_paths.service_file.unlink(missing_ok=True)
        listener.close()


def main() -> None:
    """Print connection metadata for Tauri or run the detached service."""
    if "--serve" in sys.argv[1:]:
        serve()
        return
    descriptor = connect_or_start()
    print(json.dumps({"url": descriptor.url, "token": descriptor.token}))


if __name__ == "__main__":
    main()
