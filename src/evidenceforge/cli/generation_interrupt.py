"""Cooperative SIGINT handling for long-running generation."""

from __future__ import annotations

import os
import signal
from collections.abc import Iterator
from contextlib import contextmanager
from types import FrameType


class GenerationInterruptController:
    """Latch one graceful interrupt request and force-exit on the second."""

    def __init__(self, *, checkpoint_enabled: bool, output_fd: int = 2) -> None:
        self._checkpoint_enabled = checkpoint_enabled
        self._output_fd = output_fd
        self._requested = False

    @property
    def requested(self) -> bool:
        """Return whether the first SIGINT requested graceful suspension."""

        return self._requested

    def _write_message(self, message: bytes) -> None:
        """Write one signal-path message without entering Rich rendering."""

        try:
            os.write(self._output_fd, message)
        except OSError:
            pass

    def _handle_sigint(self, _signum: int, _frame: FrameType | None) -> None:
        if not self._requested:
            self._requested = True
            if self._checkpoint_enabled:
                self._write_message(
                    b"\nInterrupt requested; generation will stop at the end of the current "
                    b"simulated hour after creating a recovery checkpoint. Press Ctrl+C again "
                    b"to force exit.\n"
                )
            else:
                self._write_message(
                    b"\nInterrupt requested; generation will stop at the end of the current "
                    b"simulated hour. Checkpoint creation is disabled, so no new recovery point "
                    b"will be created. Press Ctrl+C again to force exit.\n"
                )
            return
        self._write_message(
            b"\nSecond interrupt received; forcing immediate exit. Any previously published "
            b"recovery checkpoint remains authoritative.\n"
        )
        os._exit(130)

    @contextmanager
    def installed(self) -> Iterator[None]:
        """Install the cooperative SIGINT handler for one generation call."""

        previous = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, self._handle_sigint)
        try:
            yield
        finally:
            signal.signal(signal.SIGINT, previous)


__all__ = ["GenerationInterruptController"]
