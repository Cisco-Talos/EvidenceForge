"""Versioned runtime retention, launch leases, and conservative macOS cleanup.

This disposable installation cache has its own contracts. It never interprets
or changes the Studio database, workspace, or versioned UI settings envelope.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import psutil
from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.studio.ownership import current_account, process_account, require_owned
from evidenceforge.studio.runtime import RuntimeRelease, runtime_root
from evidenceforge.studio.state_io import (
    StateLock,
    StudioStateError,
    atomic_write,
    open_regular,
    parent_handle,
    safe_path,
)

logger = logging.getLogger(__name__)
_NAME = re.compile(r"^[a-f0-9]{64}-(?:aarch64|x86_64)$")
_DAY = 86400
_lease_descriptor: int | None = None


class RuntimeCleanupSettings(BaseModel):
    """Independent, immutable v1 configuration for the disposable runtime cache."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, strict=True, ge=1, le=1)
    previous_runtime_days: int = Field(default=30, strict=True, ge=0, le=3650)


class RuntimeRetirement(BaseModel):
    """Pinned directory identity, published before an authenticated retirement rename."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    device: int = Field(ge=0, strict=True)
    inode: int = Field(gt=0, strict=True)


class RuntimeHistory(BaseModel):
    """V1 successful-launch history and recoverable cleanup intent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, strict=True, ge=1, le=1)
    current: str | None = Field(default=None, pattern=_NAME.pattern)
    previous: str | None = Field(default=None, pattern=_NAME.pattern)
    replaced_at: float = Field(default=0, ge=0, allow_inf_nan=False)
    first_seen: dict[str, float] = Field(default_factory=dict)
    retiring: dict[str, RuntimeRetirement] = Field(default_factory=dict)


class RuntimeCleanupWarning(BaseModel):
    """An eligible runtime retained because removal could not be verified or completed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: Path
    message: str


class RuntimeCleanupReport(BaseModel):
    """Current cleanup outcome, including warnings that survive a UI reconnect."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    available: bool = False
    settings: RuntimeCleanupSettings = Field(default_factory=RuntimeCleanupSettings)
    checked_at: float | None = None
    removed: list[str] = Field(default_factory=list)
    warnings: list[RuntimeCleanupWarning] = Field(default_factory=list)


def _read(path: Path) -> bytes:
    with os.fdopen(open_regular(path, os.O_RDONLY), "rb") as stream:
        value = stream.read(1024 * 1024 + 1)
    if len(value) > 1024 * 1024:
        raise StudioStateError("Runtime cleanup metadata exceeds its size limit")
    return value


def _lease(root: Path, *, exclusive: bool) -> int:
    import fcntl

    path = root.parent / "leases" / f"{root.name}.lock"
    from evidenceforge.studio.state_io import private_directory

    private_directory(path.parent)
    descriptor = open_regular(path, os.O_RDWR | os.O_CREAT)
    try:
        fcntl.flock(descriptor, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
    except OSError:
        os.close(descriptor)
        raise
    return descriptor


@contextmanager
def runtime_lease() -> Iterator[None]:
    """Protect the helper and let detached CLI workers inherit its kernel-held lease."""
    global _lease_descriptor
    root = runtime_root()
    if root is None or os.name != "posix":
        yield
        return
    if not _NAME.fullmatch(root.name):
        raise StudioStateError("Studio's selected runtime has an invalid cache identity")
    lock = StateLock(root.parent / "install.lock")
    deadline = time.monotonic() + 8
    while True:
        try:
            lock.acquire()
            break
        except StudioStateError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)
    with lock:
        descriptor = _lease(root, exclusive=False)
    previous = _lease_descriptor
    _lease_descriptor = descriptor
    try:
        yield
    finally:
        _lease_descriptor = previous
        os.close(descriptor)


def runtime_worker_fds() -> tuple[int, ...]:
    """Keep a selected runtime alive even if its owning helper unexpectedly exits."""
    return (_lease_descriptor,) if _lease_descriptor is not None else ()


def _process_use(root: Path) -> tuple[bool, str | None]:
    """Also protect unleased commands; refuse a census with unknown account ownership."""
    account = current_account()
    uncertain: str | None = None
    try:
        for process in psutil.process_iter():
            try:
                if process_account(process) != account:
                    continue
                if process.status() == psutil.STATUS_ZOMBIE:
                    continue
                values = [process.exe(), *process.cmdline()]
                if any(str(root) in value for value in values):
                    return True, None
            except psutil.NoSuchProcess:
                continue
            except (psutil.AccessDenied, OSError, StudioStateError):
                uncertain = (
                    f"Cannot inspect process {process.pid} to verify this runtime is unused."
                )
    except (OSError, psutil.AccessDenied):
        uncertain = "Cannot inspect the process list to verify this runtime is unused."
    return False, uncertain


class RuntimeCleanup:
    """Prune only identified, expired, unused standalone runtime installations."""

    def __init__(self, data: Path, selected: Path | None = None) -> None:
        self.directory = data / "runtimes"
        self.selected = selected if selected is not None else runtime_root()
        self.report = RuntimeCleanupReport(available=self.selected is not None)

    @property
    def settings_path(self) -> Path:
        """Location of the separately versioned cache configuration."""
        return self.directory / "cleanup-settings.json"

    def settings(self) -> RuntimeCleanupSettings:
        """Read supported configuration without silently resetting malformed/newer files."""
        try:
            return RuntimeCleanupSettings.model_validate_json(_read(self.settings_path))
        except FileNotFoundError:
            return RuntimeCleanupSettings()

    def save_settings(self, settings: RuntimeCleanupSettings) -> None:
        """Atomically save supported v1 configuration under installer ownership."""
        with StateLock(self.directory / "install.lock"):
            self.settings()
            atomic_write(self.settings_path, settings.model_dump_json().encode())

    def _history(self) -> RuntimeHistory:
        try:
            history = RuntimeHistory.model_validate_json(_read(self.directory / "usage.json"))
        except FileNotFoundError:
            return RuntimeHistory()
        if (
            any(not _NAME.fullmatch(name) for name in (*history.first_seen, *history.retiring))
            or any(not 0 <= value <= time.time() + 60 for value in history.first_seen.values())
            or history.replaced_at > time.time() + 60
        ):
            raise StudioStateError("Runtime usage history contains invalid identities or times")
        return history

    def _save(self, history: RuntimeHistory) -> None:
        atomic_write(self.directory / "usage.json", history.model_dump_json().encode())

    def successful_launch(self, *, now: float | None = None) -> None:
        """Record replacement only after the selected helper initializes successfully."""
        if self.selected is None:
            return
        timestamp = now if now is not None else time.time()
        try:
            with StateLock(self.directory / "install.lock"):
                self._selected()
                history = self._history()
                if history.current != self.selected.name:
                    history = history.model_copy(
                        update={
                            "previous": history.current,
                            "current": self.selected.name,
                            "replaced_at": timestamp,
                        }
                    )
                self._save(history)
        except (OSError, ValueError, StudioStateError) as error:
            self._warn(self.directory, f"Runtime launch history could not be verified: {error}")

    def _selected(self) -> None:
        if (
            self.selected is None
            or self.selected.parent != self.directory
            or not _NAME.fullmatch(self.selected.name)
        ):
            raise StudioStateError("Selected runtime is outside Studio's runtime cache")
        self._receipt(self.selected, self.selected.name)

    def _receipt(self, path: Path, name: str) -> None:
        safe_path(path)
        require_owned(path.lstat())
        if not path.is_dir():
            raise StudioStateError("Runtime installation is not a directory")
        release = RuntimeRelease.model_validate_json(_read(path / "release.json"))
        if name != f"{release.runtime_id}-{release.architecture}":
            raise StudioStateError("Runtime receipt does not match its folder identity")

    def _warn(self, path: Path, message: str) -> None:
        warning = RuntimeCleanupWarning(path=path, message=message)
        self.report = self.report.model_copy(update={"warnings": [*self.report.warnings, warning]})
        logger.warning("Studio retained runtime %s: %s", path, message)

    def clean(self, *, now: float | None = None) -> RuntimeCleanupReport:
        """Publish one completed report; reconnecting clients retain warnings during retries."""
        worker = RuntimeCleanup(self.directory.parent, self.selected)
        report = worker._clean(now=now)
        self.report = report
        return report

    def _clean(self, *, now: float | None = None) -> RuntimeCleanupReport:
        """Recheck age, identity, leases and process use under the installer lock."""
        timestamp = now if now is not None else time.time()
        self.report = RuntimeCleanupReport(
            available=self.selected is not None, checked_at=timestamp
        )
        if self.selected is None:
            try:
                self.report = self.report.model_copy(update={"settings": self.settings()})
            except (OSError, ValueError, StudioStateError) as error:
                self._warn(self.directory, f"Runtime cleanup settings could not be read: {error}")
            return self.report
        try:
            with StateLock(self.directory / "install.lock"):
                settings = self.settings()
                self.report = self.report.model_copy(update={"settings": settings})
                self._selected()
                history = self._history()
                # A helper superseded by a newer successful launch cannot prune that launch.
                protected = {self.selected.name, history.current}
                candidates: list[tuple[Path, str]] = []
                for path in sorted(self.directory.iterdir()):
                    name = path.name
                    if name.startswith(".retired-"):
                        name = name.removeprefix(".retired-")
                        if name not in history.retiring:
                            continue
                    if not _NAME.fullmatch(name) or name in protected:
                        continue
                    history.first_seen.setdefault(name, timestamp)
                    if timestamp - history.first_seen[name] < _DAY:
                        continue
                    if (
                        name == history.previous
                        and timestamp - history.replaced_at < settings.previous_runtime_days * _DAY
                    ):
                        continue
                    candidates.append((path, name))
                # Publish first sighting before deletion; unknown legacy folders get a full grace day.
                self._save(history)
                for path, name in candidates:
                    descriptor: int | None = None
                    try:
                        already_retired = path.name == f".retired-{name}"
                        if already_retired:
                            safe_path(path)
                            metadata = path.lstat()
                            require_owned(metadata)
                            proof = history.retiring[name]
                            if (metadata.st_dev, metadata.st_ino) != (proof.device, proof.inode):
                                raise StudioStateError("Retired runtime directory identity changed")
                        else:
                            self._receipt(path, name)
                            if _read(path / ".cleanup-lease-v1") != b"1\n":
                                raise StudioStateError(
                                    "Runtime launch-lease contract is unsupported"
                                )
                        try:
                            descriptor = _lease(self.directory / name, exclusive=True)
                        except BlockingIOError:
                            continue  # Verified live lease: retention is intentional, not uncertain.
                        used, uncertain = _process_use(self.directory / name)
                        if already_retired and not used and not uncertain:
                            used, uncertain = _process_use(path)
                        if uncertain:
                            raise StudioStateError(uncertain)
                        if used:
                            continue
                        if not shutil.rmtree.avoids_symlink_attacks:
                            raise StudioStateError("Safe directory removal is unavailable")
                        retired = self.directory / f".retired-{name}"
                        if path != retired:
                            self._receipt(path, name)
                            if retired.exists() or retired.is_symlink():
                                raise StudioStateError("An earlier retirement must be inspected")
                            metadata = path.lstat()
                            history.retiring[name] = RuntimeRetirement(
                                device=metadata.st_dev, inode=metadata.st_ino
                            )
                            self._save(history)
                            parent = parent_handle(path)
                            try:
                                os.rename(
                                    path.name,
                                    retired.name,
                                    src_dir_fd=parent,
                                    dst_dir_fd=parent,
                                )
                                path = retired
                                # A crash during removal must leave a retired installation,
                                # never a partially deleted launchable runtime name.
                                os.fsync(parent)
                            finally:
                                os.close(parent)
                        shutil.rmtree(retired)
                        history.first_seen.pop(name, None)
                        history.retiring.pop(name, None)
                        self._save(history)
                        self.report.removed.append(name)
                    except FileNotFoundError:
                        self._warn(
                            path,
                            "This older runtime lacks a verifiable cleanup contract. It was kept; "
                            "inspect it after quitting older Studio builds and their background work.",
                        )
                    except (OSError, ValueError, StudioStateError) as error:
                        self._warn(path, f"Could not verify or complete safe removal: {error}")
                    finally:
                        if descriptor is not None:
                            os.close(descriptor)
        except (OSError, ValueError, StudioStateError) as error:
            self._warn(self.directory, f"Automatic runtime cleanup is paused: {error}")
        return self.report
