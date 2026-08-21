# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Base class for host-based emitters with per-host FQDN directory multiplexing.

Host-based logs (Windows events, eCAR, syslog) are organized by the originating
host's FQDN. Each host gets its own subdirectory:

    base_dir/<host-fqdn>/windows_event_security.xml
    base_dir/<host-fqdn>/ecar.json
    base_dir/<host-fqdn>/syslog.log
    base_dir/<host-fqdn>/<year>/syslog.log  # target-specific syslog layouts
"""

import hashlib
import logging
import os
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from queue import Empty
from threading import Condition, Lock, get_ident
from typing import Any

from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.base import (
    ExactPublicationError,
    ExactPublicationKey,
    ExactPublicationParticipantKey,
    LogEmitter,
    complete_exact_publication_queue_item,
    exact_publication_attempt_active,
    exact_publication_queue_payload,
    exact_publication_worker_attempt,
    fsync_directory,
    stage_exact_publication_row,
)
from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
from evidenceforge.utils.paths import sanitize_path_component

logger = logging.getLogger(__name__)


# Backward-compat alias so existing imports (tests, etc.) still work.
sanitize_host_routing_key = sanitize_path_component


class _SingleHostWriter:
    """Writes log output for one host. Thread-safe via lock."""

    def __init__(
        self,
        output_path: Path,
        buffer_size: int = 10000,
        sort_on_flush: bool = False,
        sort_key: Callable[[str], Any] | None = None,
        defer_sorted_flush_until_close: bool = False,
        external_sorting: bool = False,
    ):
        self.output_path = output_path
        self.buffer: list[str] = []
        self.buffer_size = buffer_size
        self.event_count = 0
        self._lock = Lock()
        self._header_written = False
        self._header: str | None = None
        self._footer_pending: tuple[str, int, int] | None = None
        self._footer_written = False
        self._closed = False
        self._sort_on_flush = sort_on_flush
        self._sort_key = sort_key or (lambda line: line[:15])
        self._defer_sorted_flush_until_close = defer_sorted_flush_until_close
        self._sorted_writer = (
            ExternalSortedLineWriter(
                output_path,
                sort_key=self._sort_key,
                buffer_size=buffer_size,
            )
            if sort_on_flush and external_sorting
            else None
        )
        self._exact_publication_receipts: dict[ExactPublicationKey, str] = {}
        self._exact_file_pending: dict[ExactPublicationKey, tuple[str, int, int]] = {}
        self._exact_publication_condition = Condition(Lock())
        self._active_exact_publication_keys: set[ExactPublicationParticipantKey] = set()
        self._close_state = "open"
        self._close_thread: int | None = None

    def write(self, rendered: str) -> None:
        if self._sorted_writer is not None:
            with self._exact_publication_condition:
                self._require_open_locked()
                self._sorted_writer.write(rendered)
                self.event_count = self._sorted_writer.event_count
            return
        if self._sort_on_flush:
            if exact_publication_attempt_active():
                raise ExactPublicationError(
                    "Exact sorted host output requires its external final-writer journal"
                )
        if stage_exact_publication_row(
            self,
            rendered,
            publish=self._commit_exact_row,
            release=self._release_exact_row,
        ):
            return
        with self._exact_publication_condition:
            while self._active_exact_publication_keys:
                self._exact_publication_condition.wait()
            self._require_open_locked()
            with self._lock:
                self.buffer.append(rendered)
                self.event_count += 1
                if not self._sort_on_flush and len(self.buffer) >= self.buffer_size:
                    self._flush_unlocked()

    def _commit_exact_row(
        self,
        key: ExactPublicationKey,
        digest: str,
        frozen: object,
    ) -> None:
        if type(frozen) is not str:
            raise ExactPublicationError("Exact host row must retain one exact str")
        rendered = frozen
        payload = (rendered if rendered.endswith("\n") else f"{rendered}\n").encode("utf-8")
        participant_key = key[:2]
        with self._exact_publication_condition:
            if participant_key not in self._active_exact_publication_keys:
                raise ExactPublicationError("Exact host row lost its writer fence")
            with self._lock:
                retained = self._exact_publication_receipts.get(key)
                if retained is not None:
                    if retained != digest:
                        raise ExactPublicationError("Exact host publication row changed on retry")
                    return
                self._flush_unlocked()
                self._write_header_unlocked()
                self.output_path.parent.mkdir(parents=True, exist_ok=True)
                pending = self._exact_file_pending.get(key)
                if pending is None:
                    offset = self.output_path.stat().st_size if self.output_path.exists() else 0
                    pending = (digest, offset, len(payload))
                    self._exact_file_pending[key] = pending
                pending_digest, offset, payload_length = pending
                if pending_digest != digest or payload_length != len(payload):
                    raise ExactPublicationError("Exact host admission changed on retry")
                mode = "r+b" if self.output_path.exists() else "w+b"
                with open(self.output_path, mode) as output:
                    output.seek(offset)
                    retained_payload = output.read(payload_length)
                    if retained_payload == payload:
                        output.flush()
                        os.fsync(output.fileno())
                    else:
                        if retained_payload:
                            if not payload.startswith(retained_payload):
                                raise ExactPublicationError(
                                    "Exact host admission found conflicting bytes"
                                )
                            output.seek(0, os.SEEK_END)
                            if output.tell() != offset + len(retained_payload):
                                raise ExactPublicationError(
                                    "Exact host partial admission was overtaken"
                                )
                            output.truncate(offset)
                        output.seek(offset)
                        output.write(payload)
                        output.flush()
                        os.fsync(output.fileno())
                        output.seek(offset)
                        if output.read(payload_length) != payload:
                            raise ExactPublicationError(
                                "Exact host admission did not retain its bytes"
                            )
                fsync_directory(self.output_path.parent)
                self.event_count += 1
                self._exact_publication_receipts[key] = digest

    def _release_exact_row(self, key: ExactPublicationKey) -> None:
        with self._lock:
            self._exact_publication_receipts.pop(key, None)
            self._exact_file_pending.pop(key, None)

    def _register_exact_publication_batch(
        self,
        key: ExactPublicationParticipantKey,
    ) -> None:
        with self._exact_publication_condition:
            foreign = self._active_exact_publication_keys - {key}
            if foreign:
                raise ExactPublicationError(
                    "Host writer already has an unresolved exact publication"
                )
            if self._close_state != "open" and key not in self._active_exact_publication_keys:
                raise ExactPublicationError(
                    "Host writer is closing or closed during exact publication"
                )
            self._active_exact_publication_keys.add(key)

    def _complete_exact_publication_batch(
        self,
        key: ExactPublicationParticipantKey,
    ) -> None:
        with self._exact_publication_condition:
            self._active_exact_publication_keys.discard(key)
            self._exact_publication_condition.notify_all()

    def _abort_exact_publication_batch(
        self,
        key: ExactPublicationParticipantKey,
    ) -> None:
        self._complete_exact_publication_batch(key)

    def _wait_for_exact_publications(self) -> None:
        with self._exact_publication_condition:
            while self._active_exact_publication_keys:
                self._exact_publication_condition.wait()

    def write_header(self, header: str) -> None:
        """Retain a header for the first ordinary or exact final-writer commit."""

        with self._lock:
            if self._header is not None and self._header != header:
                raise ExactPublicationError("Host writer header changed after configuration")
            self._header = header

    def _write_header_unlocked(self) -> None:
        if self._header_written or self._header is None:
            return
        header = self._header if self._header.endswith("\n") else f"{self._header}\n"
        payload = header.encode("utf-8")
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        if self.output_path.exists() and self.output_path.stat().st_size:
            with self.output_path.open("rb") as stream:
                retained = stream.read(len(payload))
            if retained != payload:
                raise ExactPublicationError("Host writer found a conflicting existing header")
            self._header_written = True
            return
        with self.output_path.open("wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        fsync_directory(self.output_path.parent)
        self._header_written = True

    def flush(self, force: bool = False) -> None:
        if self._sorted_writer is not None:
            with self._exact_publication_condition:
                self._require_open_locked()
                self._sorted_writer.flush()
                self.event_count = self._sorted_writer.event_count
            return
        with self._exact_publication_condition:
            while self._active_exact_publication_keys:
                self._exact_publication_condition.wait()
            self._require_open_locked()
            with self._lock:
                if self._sort_on_flush and self._defer_sorted_flush_until_close and not force:
                    return
                self._flush_unlocked()

    def close(self) -> None:
        """Publish every retained row while preserving retryable sorted runs."""

        owner_thread = get_ident()
        with self._exact_publication_condition:
            while self._close_state == "closing":
                if self._close_thread == owner_thread:
                    raise RuntimeError("Host writer close cannot be re-entered")
                self._exact_publication_condition.wait()
            if self._close_state == "closed":
                return
            self._close_state = "closing"
            self._close_thread = owner_thread
            while self._active_exact_publication_keys:
                self._exact_publication_condition.wait()
        try:
            if self._sorted_writer is not None:
                self._sorted_writer.close()
                self.event_count = self._sorted_writer.event_count
            else:
                with self._lock:
                    self._flush_unlocked()
        except BaseException:
            with self._exact_publication_condition:
                self._close_state = "open"
                self._close_thread = None
                self._exact_publication_condition.notify_all()
            raise
        with self._exact_publication_condition:
            if self._active_exact_publication_keys:
                raise ExactPublicationError("Host writer cannot close with unresolved exact rows")
            self._closed = True
            self._close_state = "closed"
            self._close_thread = None
            self._exact_publication_condition.notify_all()

    def _require_open_locked(self) -> None:
        if self._close_state != "open":
            raise RuntimeError("cannot write to a closed host writer")

    def _flush_unlocked(self) -> None:
        if not self.buffer:
            return
        if self._sort_on_flush:
            self.buffer.sort(key=self._sort_key)
        self._write_header_unlocked()
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.output_path, "a", encoding="utf-8") as f:
            for entry in self.buffer:
                f.write(entry)
                if not entry.endswith("\n"):
                    f.write("\n")
        self.buffer.clear()

    def write_footer(self, footer: str) -> None:
        """Write a footer (e.g., XML root closing tag) after all events."""
        self.close()
        with self._lock:
            if self._footer_written:
                return
            self._write_header_unlocked()
            encoded = footer if footer.endswith("\n") else f"{footer}\n"
            payload = encoded.encode()
            digest = hashlib.sha256(payload).hexdigest()
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            if self._footer_pending is None:
                offset = self.output_path.stat().st_size if self.output_path.exists() else 0
                self._footer_pending = (digest, offset, len(payload))
            pending_digest, offset, payload_length = self._footer_pending
            if pending_digest != digest or payload_length != len(payload):
                raise ExactPublicationError("Host writer footer changed during retry")
            mode = "r+b" if self.output_path.exists() else "w+b"
            with self.output_path.open(mode) as output:
                output.seek(offset)
                retained = output.read(payload_length)
                if retained == payload:
                    output.flush()
                    os.fsync(output.fileno())
                else:
                    if retained:
                        if not payload.startswith(retained):
                            raise ExactPublicationError(
                                "Host writer footer found conflicting bytes"
                            )
                        output.seek(0, os.SEEK_END)
                        if output.tell() != offset + len(retained):
                            raise ExactPublicationError(
                                "Host writer footer partial write was overtaken"
                            )
                        output.truncate(offset)
                    output.seek(offset)
                    output.write(payload)
                    output.flush()
                    os.fsync(output.fileno())
            fsync_directory(self.output_path.parent)
            self._footer_written = True


class HostMultiplexEmitter(LogEmitter):
    """Base class for host-based emitters with per-FQDN directory routing.

    Subclasses implement:
    - _render_event(): Convert event data to formatted string
    - can_handle(): Filter canonical occurrences
    - emit(): Extract host FQDN and call emit_to_host()
    """

    _log_filename: str = "output.log"
    _flat_filename: str = ""
    _supported_types: set[str] = set()
    _sort_flat_file: bool = False
    _sort_key: Callable[[str], Any] | None = None
    _defer_sorted_flush_until_close: bool = False
    _external_sorting: bool = False

    def __init__(
        self,
        format_def: FormatDefinition,
        output_path: Path,
        buffer_size: int = 10000,
        threaded: bool = False,
    ):
        # Detect direct file mode (backward compat for tests)
        self._direct_file_mode = output_path.suffix != ""
        self._base_dir = output_path.parent if self._direct_file_mode else output_path
        self._direct_file_path = output_path if self._direct_file_mode else None
        self._writers: dict[str, _SingleHostWriter] = {}
        self._writers_lock = Lock()
        self._buffer_size = buffer_size
        super().__init__(format_def, output_path, buffer_size, threaded)

    def _safe_writer_key(self, host_fqdn: str) -> str:
        """Return the writer key for a routed host value."""
        return sanitize_path_component(host_fqdn)

    def _writer_path_for_key(self, safe_writer_key: str) -> Path:
        """Return the output path for a writer key."""
        if safe_writer_key and not self._direct_file_mode:
            return self._base_dir / safe_writer_key / self._log_filename
        if self._direct_file_path:
            return self._direct_file_path
        flat_name = self._flat_filename or self._log_filename
        return self._base_dir / flat_name

    def _get_writer(self, host_fqdn: str) -> _SingleHostWriter:
        safe_host_fqdn = self._safe_writer_key(host_fqdn)
        writer = self._writers.get(safe_host_fqdn)
        if writer is not None:
            return writer
        with self._writers_lock:
            writer = self._writers.get(safe_host_fqdn)
            if writer is not None:
                return writer
            path = self._writer_path_for_key(safe_host_fqdn)
            sort = self._sort_flat_file
            writer = _SingleHostWriter(
                path,
                self._buffer_size,
                sort_on_flush=sort,
                sort_key=self._sort_key,
                defer_sorted_flush_until_close=self._defer_sorted_flush_until_close,
                external_sorting=self._external_sorting,
            )
            header_template = self.format_def.output.header_template
            if header_template:
                header = self._template_env.from_string(header_template).render()
                writer.write_header(header)
            self._writers[safe_host_fqdn] = writer
            logger.debug(f"Created host writer: {path}")
            return writer

    def emit_to_host(self, rendered: str, host_fqdn: str = "") -> None:
        """Route a rendered line to the appropriate host writer."""
        if not host_fqdn and not self._direct_file_path:
            return
        self._get_writer(host_fqdn).write(rendered)

    def emit_event(self, event_data: dict[str, Any]) -> None:
        if self.threaded:
            self._emit_threaded(event_data)
        else:
            self._begin_queue_admission(allow_exact=True)
            try:
                self._dispatch(deepcopy(event_data))
            finally:
                self._finish_queue_admission()

    def _dispatch(self, event_data: dict[str, Any]) -> None:
        rendered = self._render_event(event_data)
        host_fqdn = str(event_data.get("_host_fqdn", ""))
        self.emit_to_host(rendered, host_fqdn)

    def _run(self) -> None:
        logger.debug(f"Emitter thread started for {self.format_def.name}")
        while not self._stop_event.is_set():
            try:
                queue_item = self._event_queue.get(timeout=0.1)
                queued = None
                try:
                    if self._handle_flush_request(queue_item):
                        continue
                    event_data, queued = exact_publication_queue_payload(queue_item)
                    if not isinstance(event_data, dict):
                        raise TypeError("Emitter queue item must contain an event dictionary")
                    self._wait_for_exact_publication_turn(queued)
                    try:
                        with exact_publication_worker_attempt(queued):
                            self._dispatch(event_data)
                    except BaseException as error:
                        complete_exact_publication_queue_item(queued, error)
                        if queued is None:
                            raise
                        continue
                    complete_exact_publication_queue_item(queued, None)
                finally:
                    self._event_queue.task_done()
            except Empty:
                continue
        self.flush()
        logger.debug(f"Emitter thread stopped for {self.format_def.name}")

    def _buffer_event(self, rendered: str) -> None:
        """Override base class to route through explicit direct-file mode only."""
        if not self._direct_file_path:
            return
        self._get_writer("").write(rendered)

    def flush(self, force: bool = False) -> None:
        self._wait_for_exact_publication_turn(None)
        with self._writers_lock:
            for writer in self._writers.values():
                writer.flush(force=force)

    def _flush_unlocked(self) -> None:
        pass

    def close(self) -> None:
        if not self._begin_close():
            return
        try:
            self._wait_for_exact_publication_turn(None)
            if self.threaded:
                self.stop_thread()
            with self._writers_lock:
                for writer in self._writers.values():
                    writer.close()
        except BaseException:
            self._fail_close()
            raise
        self._finish_close()

    @property
    def event_count(self) -> int:
        return sum(w.event_count for w in self._writers.values())

    @event_count.setter
    def event_count(self, value: int) -> None:
        pass
