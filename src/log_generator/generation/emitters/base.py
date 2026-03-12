"""Base emitter class for log generation."""

import logging
import time
from abc import ABC, abstractmethod
from pathlib import Path
from queue import Queue, Empty, Full
from threading import Thread, Event, Lock
from typing import Any, Optional

from jinja2 import Template

from log_generator.formats.format_def import FormatDefinition

logger = logging.getLogger(__name__)


class LogEmitter(ABC):
    """Abstract base class for log emitters.

    Emitters write log events to files in specific formats. Each emitter:
    - Buffers events (default 10K) before flushing to disk
    - Uses format definitions to render events
    - Writes to a specific output file

    Phase 2.1 adds optional threaded mode:
    - Events posted to bounded queue (non-blocking)
    - Background thread consumes queue and renders events
    - Hour-level barriers for temporal consistency

    Subclasses must implement:
    - emit_event(): Process and buffer a single event
    - _render_event(): Convert event data to formatted string
    """

    def __init__(
        self,
        format_def: FormatDefinition,
        output_path: Path,
        buffer_size: int = 10000,
        threaded: bool = False,
    ):
        """Initialize emitter.

        Args:
            format_def: Format definition for this log type
            output_path: Path to write log file
            buffer_size: Number of events to buffer before flushing (default: 10K)
            threaded: Enable threaded mode with queue-based processing (Phase 2.1)
        """
        self.format_def = format_def
        self.output_path = output_path
        self.buffer_size = buffer_size
        self.buffer: list[str] = []
        self.event_count = 0
        self._template = Template(format_def.output.template)
        self._header_written = False
        self._file_lock = Lock()  # Thread-safe file I/O and buffer access

        # Threading support (Phase 2.1)
        self.threaded = threaded
        self._event_queue: Optional[Queue] = None
        self._flush_barrier: Optional[Event] = None
        self._stop_event: Optional[Event] = None
        self._thread: Optional[Thread] = None

        if self.threaded:
            self._event_queue = Queue(maxsize=50000)  # Bounded queue for backpressure
            self._flush_barrier = Event()
            self._stop_event = Event()
            self._thread = Thread(
                target=self._run,
                daemon=False,
                name=f"Emitter-{format_def.name}"
            )
            self._thread.start()
            logger.debug(f"Started emitter thread for {format_def.name}")

    @abstractmethod
    def emit_event(self, event_data: dict[str, Any]) -> None:
        """Emit a single log event.

        In threaded mode, posts to queue. In non-threaded mode, renders immediately.

        Args:
            event_data: Event data dictionary with field values
        """
        pass

    @abstractmethod
    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render event data to formatted log string.

        Args:
            event_data: Event data dictionary

        Returns:
            Formatted log entry as string
        """
        pass

    def _run(self) -> None:
        """Thread run loop - consume from queue and render events.

        This method runs in the emitter thread (not main thread).
        Continuously processes events from the queue until stop signal received.
        """
        logger.debug(f"Emitter thread started for {self.format_def.name}")

        while not self._stop_event.is_set():
            try:
                # Try to get event from queue with timeout
                event_data = self._event_queue.get(timeout=0.1)

                # Render and buffer the event
                rendered = self._render_event(event_data)
                self._buffer_event(rendered)

                # Mark task as done
                self._event_queue.task_done()

            except Empty:
                # No events in queue - check for flush barrier
                if self._flush_barrier.is_set():
                    logger.debug(f"Flushing {self.format_def.name} emitter at barrier")
                    self.flush()
                    self._flush_barrier.clear()

        # Final flush before thread exits
        logger.debug(f"Emitter thread stopping for {self.format_def.name}, final flush")
        self.flush()
        logger.debug(f"Emitter thread stopped for {self.format_def.name}")

    def _emit_threaded(self, event_data: dict[str, Any]) -> None:
        """Post event to queue in threaded mode.

        Args:
            event_data: Event data to queue
        """
        try:
            # Try non-blocking put first
            self._event_queue.put(event_data, timeout=1.0)
        except Full:
            # Queue is full - apply backpressure by blocking
            logger.warning(
                f"Event queue full for {self.format_def.name} emitter, "
                f"applying backpressure"
            )
            self._event_queue.put(event_data, block=True)

    def barrier_flush(self) -> None:
        """Signal flush and wait for completion (hour-level barrier).

        This ensures all queued events are rendered and written to disk
        before proceeding. Used for temporal consistency in Phase 2.1.
        """
        if self.threaded:
            logger.debug(f"Waiting for {self.format_def.name} emitter to flush at barrier")

            # Signal the emitter thread to flush
            self._flush_barrier.set()

            # Wait for queue to drain
            self._event_queue.join()

            # Wait for flush to complete (barrier cleared by emitter thread)
            while self._flush_barrier.is_set():
                time.sleep(0.01)

            logger.debug(f"Barrier flush complete for {self.format_def.name}")
        else:
            # Non-threaded mode: just flush directly
            self.flush()

    def stop_thread(self) -> None:
        """Gracefully shutdown emitter thread.

        Signals the thread to stop, waits for it to complete, and performs
        final flush. Call this during shutdown or cleanup.
        """
        if self.threaded and self._thread and self._thread.is_alive():
            logger.info(f"Stopping emitter thread for {self.format_def.name}")
            self._stop_event.set()
            self._thread.join(timeout=5.0)

            if self._thread.is_alive():
                logger.warning(
                    f"Emitter thread for {self.format_def.name} did not stop "
                    f"within timeout"
                )

    def _write_header(self) -> None:
        """Write header to output file if format has one (thread-safe)."""
        with self._file_lock:
            self._write_header_unlocked()

    def _write_header_unlocked(self) -> None:
        """Internal header write (must hold _file_lock).

        Private method called while already holding the lock.
        """
        if self.format_def.output.header_template and not self._header_written:
            header_template = Template(self.format_def.output.header_template)
            header = header_template.render()

            # Write header to file
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.output_path, "w", encoding=self.format_def.output.encoding) as f:
                f.write(header)
                if not header.endswith("\n"):
                    f.write("\n")

            self._header_written = True

    def _buffer_event(self, rendered: str) -> None:
        """Add rendered event to buffer and flush if needed (thread-safe).

        Args:
            rendered: Rendered event string
        """
        with self._file_lock:
            self.buffer.append(rendered)
            self.event_count += 1

            if len(self.buffer) >= self.buffer_size:
                self._flush_unlocked()

    def flush(self) -> None:
        """Flush buffered events to disk (thread-safe)."""
        with self._file_lock:
            self._flush_unlocked()

    def _flush_unlocked(self) -> None:
        """Internal flush implementation (must hold _file_lock).

        Private method called while already holding the lock.
        """
        if not self.buffer:
            return

        # Ensure header is written first (or mark as done if no header)
        if not self._header_written:
            self._write_header_unlocked()
            # Mark header as written even if no header template exists,
            # so subsequent flushes use append mode instead of truncating
            self._header_written = True

        # Ensure output directory exists
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

        # Append buffered events to file
        mode = "a" if self._header_written else "w"
        with open(self.output_path, mode, encoding=self.format_def.output.encoding) as f:
            for event in self.buffer:
                f.write(event)
                if not event.endswith("\n"):
                    f.write("\n")

        # Clear buffer immediately to release memory
        self.buffer.clear()

    def close(self) -> None:
        """Close emitter and flush any remaining events."""
        if self.threaded:
            self.stop_thread()
        self.flush()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
