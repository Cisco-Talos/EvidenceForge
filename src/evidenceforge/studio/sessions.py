"""Window leases and the helper's idle shutdown grace period."""

from __future__ import annotations

import time
from collections.abc import Callable

import psutil
from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.studio.ownership import current_account, process_account
from evidenceforge.studio.state_io import StudioStateError


class NativeApplication(BaseModel):
    """The native shell's process identity, including protection against PID reuse."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pid: int = Field(gt=0, strict=True)
    created_at: float = Field(gt=0, allow_inf_nan=False)

    def alive(self) -> bool:
        """Retain uncertain ownership; release exited or replaced processes."""
        try:
            process = psutil.Process(self.pid)
            return (
                abs(process.create_time() - self.created_at) < 0.01
                and process.is_running()
                and process.status() != psutil.STATUS_ZOMBIE
            )
        except psutil.NoSuchProcess:
            return False
        except (psutil.AccessDenied, OSError):
            return True


class WindowSessions:
    """Keep a helper alive for windows, including maintenance and reconnects.

    Leases cover unannounced window/process exits. Explicit close tombstones prevent
    a heartbeat in flight from undoing the close handoff. Only opening again clears
    a tombstone; heartbeats never change persisted quit policies.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        lease_seconds: float = 120,
        idle_seconds: float = 8,
    ) -> None:
        self.clock = clock
        self.lease_seconds = lease_seconds
        self.idle_seconds = idle_seconds
        self.started_at = clock()
        self.windows: dict[str, float] = {}
        self.applications: dict[str, NativeApplication] = {}
        self.closed: set[str] = set()
        self.attached = False
        self.idle_since: float | None = None
        self.exit_requested = False

    def bind_application(self, session: str, pid: int | None, created_at: float | None) -> None:
        """Bind an authenticated window to its verified native shell when available."""
        if pid is None and created_at is None:
            return
        if pid is None or created_at is None:
            raise ValueError("Studio application identity requires PID and creation time")
        application = NativeApplication(pid=pid, created_at=created_at)
        if self.applications.get(session) == application:
            return
        process = psutil.Process(pid)
        if (
            process_account(process) != current_account()
            or abs(process.create_time() - created_at) >= 0.01
            or not process.is_running()
            or process.status() == psutil.STATUS_ZOMBIE
        ):
            raise StudioStateError("Studio application identity changed")
        self.applications[session] = application

    def open(self, session: str) -> None:
        """Attach a window or cancel its close handoff."""
        self.closed.discard(session)
        self.heartbeat(session)

    def heartbeat(self, session: str) -> None:
        """Refresh a live window without resurrecting one that has closed."""
        if session not in self.closed:
            self.windows[session] = self.clock()
            self.attached = True
            self.idle_since = None
            self.exit_requested = False

    def close(self, session: str, *, proactive: bool = False) -> None:
        """Detach one window after its quit handoff succeeds."""
        self.windows.pop(session, None)
        self.applications.pop(session, None)
        self.closed.add(session)
        self.attached = True
        if proactive and not self.windows:
            self.exit_requested = True

    def has_other_windows(self, session: str) -> bool:
        """Return whether another unexpired window owns the helper."""
        self._expire()
        return any(window != session for window in self.windows)

    def _expire(self) -> None:
        now = self.clock()
        for window, application in tuple(self.applications.items()):
            if window not in self.windows:
                self.applications.pop(window, None)
            elif not application.alive():
                self.close(window, proactive=False)
        self.windows = {
            window: seen
            for window, seen in self.windows.items()
            if window in self.applications or now - seen < self.lease_seconds
        }

    def should_exit(self, busy: bool) -> bool:
        """Exit only after windows and protected work have stayed absent."""
        self._expire()
        now = self.clock()
        starting = not self.attached and now - self.started_at < self.lease_seconds
        if busy or self.windows or starting:
            self.idle_since = None
            return False
        if self.exit_requested:
            return True
        if self.idle_since is None:
            self.idle_since = now
        return now - self.idle_since >= self.idle_seconds
