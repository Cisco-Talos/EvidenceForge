"""Explicit stream methods for Windows' delegated temporary-file wrapper."""

import tempfile
from typing import BinaryIO


class WindowsTemporaryStream:
    """Own a temporary file and expose the operations captured by storage registries."""

    __slots__ = ("_stream",)

    def __init__(self, *, mode: str = "w+b") -> None:
        self._stream: BinaryIO = tempfile.TemporaryFile(mode=mode)

    def fileno(self) -> int:
        """Return the owned binary descriptor."""
        return self._stream.fileno()

    def flush(self) -> None:
        """Flush the owned stream's buffered bytes."""
        self._stream.flush()

    def close(self) -> None:
        """Close the stream and let its native temporary-file owner remove it."""
        self._stream.close()

    @property
    def closed(self) -> bool:
        """Return whether the owning stream has closed."""
        return self._stream.closed


def temporary_stream(*, mode: str = "w+b") -> WindowsTemporaryStream:
    """Create a Windows temporary stream with explicit class-level operations."""
    return WindowsTemporaryStream(mode=mode)
