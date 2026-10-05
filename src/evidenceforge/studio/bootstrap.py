"""Attach to or start the one local EvidenceForge Studio service."""

from __future__ import annotations

import json
import os
import secrets
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import psutil
import uvicorn
from pydantic import BaseModel, ConfigDict, Field

if os.name == "posix":
    import fcntl

from evidenceforge.studio.background import start_background_service
from evidenceforge.studio.paths import StudioPaths, studio_paths
from evidenceforge.studio.runtime import runtime_id
from evidenceforge.studio.service import create_app


class ServiceDescriptor(BaseModel):
    """Private capability required to connect to the loopback service."""

    model_config = ConfigDict(extra="forbid")

    pid: int
    created_at: float
    port: int
    token: str
    runtime_id: str = "source"
    executable: str | None = None

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


def _replace_idle(descriptor: ServiceDescriptor) -> None:
    """Retire only an authenticated, idle helper with verified process identity."""
    request = urllib.request.Request(
        f"{descriptor.url}/v1/runtime/prepare-replacement",
        method="POST",
        headers={"X-EForge-Token": descriptor.token},
        data=b"",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            result = ReplacementReady.model_validate_json(response.read())
    except urllib.error.HTTPError as error:
        if error.code == 409:
            raise RuntimeError(
                "Another Studio build still has active work. Finish or pause its jobs and "
                "stop active authoring before opening this build."
            ) from error
        raise RuntimeError(
            "The existing Studio helper cannot safely hand off to this build. "
            "Close its work and stop that helper before reopening Studio."
        ) from error
    if not result.ready or result.runtime_id != descriptor.runtime_id:
        raise RuntimeError("Studio's helper did not confirm an authenticated idle handoff")
    try:
        process = psutil.Process(descriptor.pid)
        command = process.cmdline()
        if (
            abs(process.create_time() - descriptor.created_at) >= 0.01
            or not descriptor.executable
            or Path(process.exe()).resolve() != Path(descriptor.executable).resolve()
            or "evidenceforge.studio.bootstrap" not in command
            or "--serve" not in command
        ):
            raise RuntimeError("Studio helper identity changed; no process was stopped")
        process.terminate()
        process.wait(timeout=8)
    except psutil.NoSuchProcess:
        return
    except (psutil.AccessDenied, psutil.TimeoutExpired) as error:
        raise RuntimeError(
            "Studio's idle helper did not exit; it was not forcibly killed"
        ) from error


class ReplacementReady(BaseModel):
    """Authenticated response required before replacing a live helper."""

    model_config = ConfigDict(extra="forbid")
    ready: bool
    runtime_id: str = Field(min_length=1)


def connect_or_start(paths: StudioPaths | None = None) -> ServiceDescriptor:
    """Return the existing service or launch a detached one and await readiness."""
    app_paths = paths or studio_paths()
    app_paths.state.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = app_paths.state / "service-start.lock"
    with lock_path.open("a+") as lock:
        if os.name == "posix":
            fcntl.flock(lock, fcntl.LOCK_EX)
        selected_runtime = runtime_id()
        descriptor = _read_descriptor(app_paths.service_file)
        if descriptor and _is_live(descriptor):
            if descriptor.runtime_id == selected_runtime:
                return descriptor
            _replace_idle(descriptor)
        app_paths.logs.mkdir(parents=True, exist_ok=True)
        start_background_service(app_paths)
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            descriptor = _read_descriptor(app_paths.service_file)
            if descriptor and descriptor.runtime_id == selected_runtime and _is_live(descriptor):
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
        runtime_id=runtime_id(),
        executable=str(Path(sys.executable).resolve()),
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
    try:
        descriptor = connect_or_start()
    except (OSError, RuntimeError, ValueError) as error:
        raise SystemExit(str(error)) from None
    print(json.dumps({"url": descriptor.url, "token": descriptor.token}))


if __name__ == "__main__":
    main()
