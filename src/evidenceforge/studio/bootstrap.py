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

from evidenceforge.studio.background import start_background_service
from evidenceforge.studio.ownership import (
    AccountIdentity,
    current_account,
    process_account,
    require_owned,
    secure_directory,
    validate_private_paths,
)
from evidenceforge.studio.paths import StudioPaths, studio_paths
from evidenceforge.studio.runtime import runtime_id
from evidenceforge.studio.runtime_cleanup import runtime_lease
from evidenceforge.studio.service import create_app
from evidenceforge.studio.state_io import (
    StateLock,
    StudioStateError,
    atomic_write,
    durable_remove,
    open_regular,
)


class ServiceDescriptor(BaseModel):
    """Private capability required to connect to the loopback service."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=0, strict=True, ge=0, le=1)
    owner: AccountIdentity | None = None
    pid: int = Field(gt=0, strict=True)
    created_at: float = Field(gt=0, allow_inf_nan=False)
    port: int = Field(ge=1, le=65535, strict=True)
    token: str = Field(min_length=1, repr=False)
    runtime_id: str = "source"
    executable: str | None = None

    @property
    def url(self) -> str:
        """Return the API origin for the desktop renderer."""
        return f"http://127.0.0.1:{self.port}"


def _read_descriptor(path: Path) -> ServiceDescriptor | None:
    """Read a bounded credential through an owned, private, no-follow handle."""
    if path.parent.exists():
        secure_directory(path.parent)
    try:
        descriptor = open_regular(path, os.O_RDONLY)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        require_owned(metadata)
        if os.name == "nt":
            from evidenceforge.utils.windows_filesystem import require_private

            require_private(stream.fileno())
        elif metadata.st_mode & 0o077:
            raise StudioStateError("Studio helper credentials must be private (file mode 600)")
        content = stream.read(16385)
    try:
        if len(content) > 16384:
            raise ValueError("oversized descriptor")
        result = ServiceDescriptor.model_validate_json(content)
    except ValueError:
        # Never include Pydantic's input values: they contain the connection token.
        raise StudioStateError(
            "Studio helper discovery is malformed or from an unsupported newer build; "
            "inspect the private service.json file before reopening"
        ) from None
    if result.schema_version == 1 and result.owner is None:
        raise StudioStateError("Studio helper discovery is missing its account identity")
    if result.owner is not None and result.owner != current_account():
        raise StudioStateError("Studio helper discovery belongs to another OS account")
    return result


def _verified_process(descriptor: ServiceDescriptor) -> psutil.Process | None:
    """Verify actual ownership, creation time and command before sending any token."""
    if descriptor.owner is not None and descriptor.owner != current_account():
        raise StudioStateError("Studio helper belongs to another OS account")
    try:
        process = psutil.Process(descriptor.pid)
        if abs(process.create_time() - descriptor.created_at) >= 0.01:
            return None  # A stale PID does not authorize connecting to or stopping its new owner.
        if process_account(process) != current_account():
            raise StudioStateError("Studio helper process belongs to another OS account")
        command = process.cmdline()
        executable = descriptor.executable or sys.executable
        if (
            Path(process.exe()).resolve() != Path(executable).resolve()
            or "-m" not in command
            or command[command.index("-m") + 1 :] != ["evidenceforge.studio.bootstrap", "--serve"]
        ):
            raise StudioStateError("Studio helper process identity changed; it cannot be used")
        if abs(process.create_time() - descriptor.created_at) >= 0.01 or not process.is_running():
            return None
        return process
    except psutil.NoSuchProcess:
        return None
    except (psutil.AccessDenied, OSError) as error:
        raise StudioStateError(
            "Cannot verify the existing Studio helper's ownership. Attachment or replacement "
            "requires verifiable ownership; retry when it can be inspected"
        ) from error


def _is_live(descriptor: ServiceDescriptor) -> bool:
    if _verified_process(descriptor) is None:
        return False
    try:
        request = urllib.request.Request(
            f"{descriptor.url}/v1/health",
            headers={"X-EForge-Token": descriptor.token},
        )
        with urllib.request.urlopen(request, timeout=0.35) as response:
            return response.status == 200
    except urllib.error.HTTPError as error:
        error.close()
        return False
    except (OSError, urllib.error.URLError, TimeoutError):
        return False


def _replace_idle(descriptor: ServiceDescriptor) -> None:
    """Retire only an authenticated, idle helper with verified process identity."""
    if _verified_process(descriptor) is None:
        raise RuntimeError("Studio helper identity changed; no process was stopped")
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
        error.close()
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
        process = _verified_process(descriptor)
        if process is None:
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
    validate_private_paths(app_paths)
    lock_path = app_paths.state / "service-start.lock"
    lock = StateLock(lock_path)
    ownership_deadline = time.monotonic() + 12
    while True:
        try:
            lock.acquire()
            break
        except StudioStateError:
            descriptor = _read_descriptor(app_paths.service_file)
            if descriptor and descriptor.runtime_id == runtime_id() and _is_live(descriptor):
                return descriptor
            if time.monotonic() >= ownership_deadline:
                raise RuntimeError(
                    "Another Studio launch is preparing the helper; retry shortly"
                ) from None
            time.sleep(0.1)
    with lock:
        selected_runtime = runtime_id()
        descriptor = _read_descriptor(app_paths.service_file)
        if descriptor and _is_live(descriptor):
            if descriptor.runtime_id == selected_runtime:
                return descriptor
            _replace_idle(descriptor)
        # An authenticated probe may fail while a verified helper is starting. Never
        # spawn a second writer merely because its HTTP listener is not ready yet.
        if descriptor is None or _verified_process(descriptor) is None:
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
    validate_private_paths(app_paths)
    with runtime_lease(), StateLock(app_paths.state / "service-instance.lock"):
        _serve(app_paths)


def _serve(app_paths: StudioPaths) -> None:
    """Publish discovery while holding exclusive helper-instance ownership."""
    existing = _read_descriptor(app_paths.service_file)
    if existing and _verified_process(existing) is not None:
        return
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        process = psutil.Process()
        descriptor = ServiceDescriptor(
            schema_version=1,
            owner=current_account(),
            pid=os.getpid(),
            created_at=process.create_time(),
            port=int(listener.getsockname()[1]),
            token=secrets.token_urlsafe(32),
            runtime_id=runtime_id(),
            executable=str(Path(process.exe()).resolve()),
        )
        atomic_write(app_paths.service_file, descriptor.model_dump_json().encode())
        try:

            def request_shutdown() -> None:
                server.should_exit = True

            app = create_app(app_paths, descriptor.token, shutdown=request_shutdown)
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
            if current == descriptor:
                durable_remove(app_paths.service_file)


def main() -> None:
    """Print connection metadata for Tauri or run the detached service."""
    if "--serve" in sys.argv[1:]:
        serve()
        return
    try:
        descriptor = connect_or_start()
    except (OSError, RuntimeError, ValueError, StudioStateError) as error:
        raise SystemExit(str(error)) from None
    print(json.dumps({"url": descriptor.url, "token": descriptor.token}))


if __name__ == "__main__":
    main()
