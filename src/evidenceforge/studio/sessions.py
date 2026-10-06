"""Window leases and the helper's idle shutdown grace period."""

from __future__ import annotations

import time
from collections.abc import Callable


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
        self.closed: set[str] = set()
        self.attached = False
        self.idle_since: float | None = None

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

    def close(self, session: str) -> None:
        """Detach one window after its quit handoff succeeds."""
        self.windows.pop(session, None)
        self.closed.add(session)
        self.attached = True

    def has_other_windows(self, session: str) -> bool:
        """Return whether another unexpired window owns the helper."""
        self._expire()
        return any(window != session for window in self.windows)

    def _expire(self) -> None:
        now = self.clock()
        self.windows = {
            window: seen for window, seen in self.windows.items() if now - seen < self.lease_seconds
        }

    def should_exit(self, busy: bool) -> bool:
        """Exit only after windows and protected work have stayed absent."""
        self._expire()
        now = self.clock()
        starting = not self.attached and now - self.started_at < self.lease_seconds
        if busy or self.windows or starting:
            self.idle_since = None
            return False
        if self.idle_since is None:
            self.idle_since = now
        return now - self.idle_since >= self.idle_seconds
