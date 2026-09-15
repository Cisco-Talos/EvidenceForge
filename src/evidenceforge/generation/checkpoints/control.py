"""Protected cooperative control records for checkpoint-enabled generation."""

from __future__ import annotations

import json
import os
import socket
import stat
import time
import uuid
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.utils.files import fsync_directory, open_host_file

from .errors import CheckpointError, CheckpointFilesystemError, CheckpointLockError
from .models import CheckpointCursor
from .store import IncrementalCheckpointStore

_CONTROL_NAME = "controller.json"
_SUSPEND_REQUEST_NAME = "suspend-request.json"
_SUSPENDED_NAME = "suspended.json"
_MAX_CONTROL_BYTES = 64 * 1024


class CheckpointControllerRecord(BaseModel):
    """Discoverable marker for a checkpoint-enabled generation controller."""

    kind: Literal["evidenceforge.generation-controller"] = "evidenceforge.generation-controller"
    schema_version: Literal["1.0"] = "1.0"
    run_id: str = Field(min_length=1)
    checkpoint_hours: int = Field(gt=0)

    model_config = ConfigDict(extra="forbid", frozen=True)


class SuspensionRequest(BaseModel):
    """One cooperative request to stop after the current simulated hour."""

    kind: Literal["evidenceforge.generation-suspend-request"] = (
        "evidenceforge.generation-suspend-request"
    )
    schema_version: Literal["1.0"] = "1.0"
    request_id: str = Field(min_length=1)
    requested_ns: int = Field(gt=0)
    hostname: str = Field(min_length=1)
    pid: int = Field(gt=0)

    model_config = ConfigDict(extra="forbid", frozen=True)


class SuspensionRecord(BaseModel):
    """Durable acknowledgement of an intentional generation suspension."""

    kind: Literal["evidenceforge.generation-suspended"] = "evidenceforge.generation-suspended"
    schema_version: Literal["1.0"] = "1.0"
    request_id: str = Field(min_length=1)
    completed_ns: int = Field(gt=0)
    cursor: CheckpointCursor

    model_config = ConfigDict(extra="forbid", frozen=True)


def _canonical_json(model: BaseModel) -> bytes:
    return json.dumps(
        model.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _atomic_write(path: Path, payload: bytes) -> None:
    if os.name == "nt":
        from .windows_io import WindowsCheckpointIO

        WindowsCheckpointIO().write_atomic(path, (payload,))
        return
    temporary = path.with_name(f".{path.name}.pending-{uuid.uuid4().hex}")
    try:
        descriptor = open_host_file(
            temporary, (os.O_WRONLY | getattr(os, "O_BINARY", 0)) | os.O_CREAT | os.O_EXCL, 0o600
        )
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:  # pragma: no cover - os.write contract
                    raise OSError("control-file write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_create(path: Path, payload: bytes) -> bool:
    """Publish a complete record only when the fixed destination is absent."""

    if os.name == "nt":
        from .windows_io import WindowsCheckpointIO

        try:
            WindowsCheckpointIO().write_new(path, payload)
        except FileExistsError:
            return False
        return True
    temporary = path.with_name(f".{path.name}.pending-{uuid.uuid4().hex}")
    try:
        descriptor = open_host_file(
            temporary, (os.O_WRONLY | getattr(os, "O_BINARY", 0)) | os.O_CREAT | os.O_EXCL, 0o600
        )
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:  # pragma: no cover - os.write contract
                    raise OSError("control-file write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.link(temporary, path)
        except FileExistsError:
            return False
        except OSError as error:
            raise CheckpointFilesystemError(
                "checkpoint control requests require atomic same-filesystem hard links"
            ) from error
        fsync_directory(path.parent)
        return True
    finally:
        temporary.unlink(missing_ok=True)


def _read_model(path: Path, model_type: type[BaseModel]) -> BaseModel | None:
    try:
        descriptor = open_host_file(
            path, (os.O_RDONLY | getattr(os, "O_BINARY", 0)) | getattr(os, "O_NOFOLLOW", 0)
        )
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise CheckpointFilesystemError(f"checkpoint control path is unsafe: {path}")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise CheckpointFilesystemError(f"checkpoint control path has an unsafe owner: {path}")
        if os.name == "posix" and info.st_mode & 0o022:
            raise CheckpointFilesystemError(
                f"checkpoint control path is externally writable: {path}"
            )
        payload = os.read(descriptor, _MAX_CONTROL_BYTES + 1)
        if len(payload) > _MAX_CONTROL_BYTES:
            raise CheckpointError(f"checkpoint control record is too large: {path.name}")
        return model_type.model_validate_json(payload)
    except (OSError, ValidationError) as error:
        raise CheckpointError(f"checkpoint control record is invalid: {path.name}") from error
    finally:
        os.close(descriptor)


def _unlink_control(path: Path) -> None:
    if os.name == "nt":
        from .windows_io import WindowsCheckpointIO

        WindowsCheckpointIO().remove_record(path)
        return
    path.unlink(missing_ok=True)


def publish_controller_record(
    store: IncrementalCheckpointStore,
    *,
    run_id: str,
    checkpoint_hours: int,
) -> None:
    """Publish checkpoint-control capability for one active controller."""

    store.initialize()
    record = CheckpointControllerRecord(run_id=run_id, checkpoint_hours=checkpoint_hours)
    _atomic_write(store.workspace / _CONTROL_NAME, _canonical_json(record))
    _unlink_control(store.workspace / _SUSPENDED_NAME)


def clear_controller_record(store: IncrementalCheckpointStore) -> None:
    """Remove checkpoint-control capability for a controller with cadence disabled."""

    for name in (_CONTROL_NAME, _SUSPEND_REQUEST_NAME, _SUSPENDED_NAME):
        _unlink_control(store.workspace / name)
    fsync_directory(store.workspace)


def read_controller_record(
    store: IncrementalCheckpointStore,
) -> CheckpointControllerRecord | None:
    """Read an existing controller capability without mutating the workspace."""

    value = _read_model(store.workspace / _CONTROL_NAME, CheckpointControllerRecord)
    return value if isinstance(value, CheckpointControllerRecord) else None


def request_suspension(store: IncrementalCheckpointStore) -> SuspensionRequest:
    """Publish a cooperative suspension request for a live checkpoint controller."""

    store.validate_existing_workspace()
    lock = store.lock.inspect()
    if lock.state not in {"active", "remote"}:
        detail = f" ({lock.detail})" if lock.detail else ""
        raise CheckpointLockError(f"no active generation owns this output{detail}")
    if read_controller_record(store) is None:
        raise CheckpointError(
            "the active generation is not checkpoint-enabled and cannot be suspended safely"
        )
    if read_suspension_record(store) is not None:
        raise CheckpointError("the active generation has already committed its suspension")
    existing = read_suspension_request(store)
    if existing is not None:
        return existing
    request = new_suspension_request()
    if _atomic_create(store.workspace / _SUSPEND_REQUEST_NAME, _canonical_json(request)):
        return request
    existing = read_suspension_request(store)
    if existing is None:  # pragma: no cover - only possible with hostile concurrent mutation
        raise CheckpointError("checkpoint suspension request changed during publication")
    return existing


def new_suspension_request() -> SuspensionRequest:
    """Create one process-local suspension identity without publishing control state."""

    return SuspensionRequest(
        request_id=uuid.uuid4().hex,
        requested_ns=time.time_ns(),
        hostname=socket.gethostname(),
        pid=os.getpid(),
    )


def read_suspension_request(
    store: IncrementalCheckpointStore,
) -> SuspensionRequest | None:
    """Read a pending cooperative request without changing it."""

    value = _read_model(store.workspace / _SUSPEND_REQUEST_NAME, SuspensionRequest)
    return value if isinstance(value, SuspensionRequest) else None


def mark_suspended(
    store: IncrementalCheckpointStore,
    *,
    request: SuspensionRequest,
    cursor: CheckpointCursor,
) -> SuspensionRecord:
    """Acknowledge a request only after its recovery manifest is durable."""

    if os.name == "nt":
        store._windows_io.require_healthy()
    record = SuspensionRecord(
        request_id=request.request_id,
        completed_ns=time.time_ns(),
        cursor=cursor,
    )
    _atomic_write(store.workspace / _SUSPENDED_NAME, _canonical_json(record))
    _unlink_control(store.workspace / _SUSPEND_REQUEST_NAME)
    fsync_directory(store.workspace)
    return record


def read_suspension_record(
    store: IncrementalCheckpointStore,
) -> SuspensionRecord | None:
    """Read an intentional-suspension acknowledgement without changing it."""

    value = _read_model(store.workspace / _SUSPENDED_NAME, SuspensionRecord)
    return value if isinstance(value, SuspensionRecord) else None
