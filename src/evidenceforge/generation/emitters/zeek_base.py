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

"""Base class for network sensor emitters with per-sensor directory multiplexing.

Network sensors each get their own output directory. This base class follows
the BashHistoryEmitter multiplexing pattern: a single emitter instance per
format, with internal routing to per-sensor subdirectories.

Output structure:
    base_dir/<sensor_hostname>/conn.json
    base_dir/<sensor_hostname>/dns.json
    base_dir/<sensor_hostname>/ssl.json
    ...

When no sensors are configured, directory-mode generation does not write
sensor logs. Direct file paths remain supported for focused tests and callers
that explicitly request one file.
"""

import json
import logging
import os
from collections.abc import Callable
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from queue import Empty
from threading import Condition, Lock, get_ident
from typing import Any

from evidenceforge.events.network import NetworkSensorObservation
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
from evidenceforge.generation.network_observation import (
    compatibility_network_source_duration,
    compatibility_network_source_time,
)
from evidenceforge.models.exceptions import EventContractError
from evidenceforge.utils.paths import sanitize_path_component

logger = logging.getLogger(__name__)


def direct_zeek_source_time(event: Any, key: str) -> datetime:
    """Return one stateless direct-call source timestamp from the owning adapter."""

    return compatibility_network_source_time(event, key)


def direct_zeek_source_duration(event: Any, key: str) -> float | None:
    """Return one stateless direct-call duration from the owning adapter."""

    return compatibility_network_source_duration(event, key)


def zeek_format_observed(event: Any, format_name: str) -> bool:
    """Return whether a Zeek sibling format survived source observation.

    Direct emitter tests and low-level callers do not run through the dispatcher,
    so an empty observed-format set means "unknown" rather than "dropped".
    """
    observed_formats = getattr(event, "_observed_formats", set())
    return not observed_formats or format_name in observed_formats


def planned_zeek_connection_interval(
    event: Any,
) -> tuple[datetime, datetime | None] | None:
    """Return the sealed canonical interval used for per-sensor projection."""

    network = getattr(event, "network", None)
    if not getattr(event, "network_observations_planned", False) or network is None:
        return None
    return network.started_at, network.closed_at


def _swap_host_list_value(value: Any, original_ip: Any, visible_ip: Any) -> Any:
    """Apply a per-sensor NAT IP view to Zeek list-valued host fields."""
    if (
        not isinstance(value, list)
        or not isinstance(original_ip, str)
        or not isinstance(visible_ip, str)
    ):
        return value
    return [visible_ip if item == original_ip else item for item in value]


def _round_zeek_float(value: float) -> float:
    """Round Zeek interval-like values to source-native microsecond precision."""
    rounded = round(value, 6)
    if rounded == 0 and value > 0:
        return 0.000001
    if rounded == 0 and value < 0:
        return -0.000001
    return rounded


def _normalize_zeek_float_precision(value: Any) -> Any:
    """Normalize floats in rendered Zeek JSON while preserving JSON structure."""
    if isinstance(value, bool):
        return value
    if isinstance(value, float):
        return _round_zeek_float(value)
    if isinstance(value, list):
        return [_normalize_zeek_float_precision(item) for item in value]
    if isinstance(value, dict):
        return {key: _normalize_zeek_float_precision(item) for key, item in value.items()}
    return value


def _enforce_http_body_invariants(render_data: dict[str, Any]) -> None:
    """Keep conn.log byte counters compatible with same-transaction http.log facts."""
    if render_data.pop("_sensor_traffic_observed", False):
        return
    request_body = render_data.get("_http_request_body_len")
    response_body = render_data.get("_http_response_body_len")
    if isinstance(request_body, int) and request_body >= 0:
        orig_bytes = render_data.get("orig_bytes")
        if isinstance(orig_bytes, int) and orig_bytes < request_body:
            render_data["orig_bytes"] = request_body
    if isinstance(response_body, int) and response_body >= 0:
        resp_bytes = render_data.get("resp_bytes")
        if isinstance(resp_bytes, int) and resp_bytes < response_body:
            render_data["resp_bytes"] = response_body


def _enforce_ip_byte_invariants(render_data: dict[str, Any]) -> None:
    """Keep projected Zeek IP-byte counters physically possible."""
    proto = str(render_data.get("proto") or "").lower()
    header_bytes = {"tcp": 40, "udp": 28, "icmp": 28}.get(proto, 20)
    max_header_bytes = {"udp": 68}.get(proto)
    for side in ("orig", "resp"):
        payload = render_data.get(f"{side}_bytes")
        ip_bytes = render_data.get(f"{side}_ip_bytes")
        packets = render_data.get(f"{side}_pkts")
        if not isinstance(payload, int) or not isinstance(ip_bytes, int):
            continue
        if payload < 0 or ip_bytes < 0:
            continue
        if packets == 0 and payload == 0:
            render_data[f"{side}_ip_bytes"] = 0
            continue
        packet_count = packets if isinstance(packets, int) and packets > 0 else 1
        if proto == "udp":
            render_data[f"{side}_ip_bytes"] = payload + (header_bytes * packet_count)
            continue
        minimum_ip_bytes = payload + (header_bytes * packet_count)
        if ip_bytes < minimum_ip_bytes:
            render_data[f"{side}_ip_bytes"] = minimum_ip_bytes
            ip_bytes = minimum_ip_bytes
        if max_header_bytes is not None:
            maximum_ip_bytes = payload + (max_header_bytes * packet_count)
            if ip_bytes > maximum_ip_bytes:
                render_data[f"{side}_ip_bytes"] = maximum_ip_bytes


class _SingleZeekWriter:
    """Writes Zeek NDJSON for one sensor. Thread-safe via lock."""

    def __init__(
        self,
        output_path: Path,
        buffer_size: int = 10000,
        sort_before_flush: bool = False,
        sort_key: Callable[[str], Any] | None = None,
        buffer_bytes: int = 16 * 1024 * 1024,
        external_sorting: bool = True,
        checkpoint_mode: bool = False,
        defer_publication: bool = False,
    ):
        self.output_path = output_path
        self.buffer: list[str] = []
        self.buffer_size = buffer_size
        self.event_count = 0
        self._lock = Lock()
        self._sort_before_flush = sort_before_flush
        self._sort_key = sort_key
        self._closed = False
        self._sorted_writer = (
            ExternalSortedLineWriter(
                output_path,
                sort_key=sort_key or (lambda line: line),
                buffer_size=buffer_size,
                buffer_bytes=buffer_bytes,
                checkpoint_mode=checkpoint_mode,
                defer_publication=defer_publication,
            )
            if sort_before_flush and external_sorting
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
        if self._sort_before_flush and exact_publication_attempt_active():
            raise ExactPublicationError(
                "Exact sorted sensor output requires its external final-writer journal"
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
                if len(self.buffer) >= self.buffer_size:
                    self._flush_unlocked()

    def _commit_exact_row(
        self,
        key: ExactPublicationKey,
        digest: str,
        frozen: object,
    ) -> None:
        if type(frozen) is not str:
            raise ExactPublicationError("Exact sensor row must retain one exact str")
        rendered = frozen
        payload = (rendered if rendered.endswith("\n") else f"{rendered}\n").encode("utf-8")
        participant_key = key[:2]
        with self._exact_publication_condition:
            if participant_key not in self._active_exact_publication_keys:
                raise ExactPublicationError("Exact sensor row lost its writer fence")
            with self._lock:
                retained = self._exact_publication_receipts.get(key)
                if retained is not None:
                    if retained != digest:
                        raise ExactPublicationError("Exact sensor publication row changed on retry")
                    return
                self._flush_unlocked()
                self.output_path.parent.mkdir(parents=True, exist_ok=True)
                pending = self._exact_file_pending.get(key)
                if pending is None:
                    offset = self.output_path.stat().st_size if self.output_path.exists() else 0
                    pending = (digest, offset, len(payload))
                    self._exact_file_pending[key] = pending
                pending_digest, offset, payload_length = pending
                if pending_digest != digest or payload_length != len(payload):
                    raise ExactPublicationError("Exact sensor admission changed on retry")
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
                                    "Exact sensor admission found conflicting bytes"
                                )
                            output.seek(0, os.SEEK_END)
                            if output.tell() != offset + len(retained_payload):
                                raise ExactPublicationError(
                                    "Exact sensor partial admission was overtaken"
                                )
                            output.truncate(offset)
                        output.seek(offset)
                        output.write(payload)
                        output.flush()
                        os.fsync(output.fileno())
                        output.seek(offset)
                        if output.read(payload_length) != payload:
                            raise ExactPublicationError(
                                "Exact sensor admission did not retain its bytes"
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
                    "Sensor writer already has an unresolved exact publication"
                )
            if self._close_state != "open" and key not in self._active_exact_publication_keys:
                raise ExactPublicationError(
                    "Sensor writer is closing or closed during exact publication"
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

    def _require_open_locked(self) -> None:
        if self._close_state != "open":
            raise RuntimeError("cannot write to a closed sensor writer")

    def flush(self) -> None:
        if self._sorted_writer is not None:
            with self._exact_publication_condition:
                self._require_open_locked()
                self._sorted_writer.flush()
            return
        with self._exact_publication_condition:
            while self._active_exact_publication_keys:
                self._exact_publication_condition.wait()
            self._require_open_locked()
            with self._lock:
                self._flush_unlocked()
                if not self._sort_before_flush or not self.output_path.exists():
                    return
                lines = self.output_path.read_text(encoding="utf-8").splitlines()
                lines.sort(key=self._sort_key or (lambda line: line))
                with self.output_path.open("w", encoding="utf-8", newline="\n") as stream:
                    for line in lines:
                        stream.write(line)
                        stream.write("\n")

    def _flush_unlocked(self) -> None:
        if not self.buffer:
            return
        if self._sort_before_flush:
            if self._sort_key:
                self.buffer.sort(key=self._sort_key)
            else:
                self.buffer.sort()
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.output_path, "a", encoding="utf-8") as f:
            for entry in self.buffer:
                f.write(entry)
                if not entry.endswith("\n"):
                    f.write("\n")
        self.buffer.clear()

    def close(self) -> None:
        """Flush pending lines and publish deterministic timestamp ordering."""
        owner_thread = get_ident()
        with self._exact_publication_condition:
            while self._close_state == "closing":
                if self._close_thread == owner_thread:
                    raise RuntimeError("Sensor writer close cannot be re-entered")
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
                raise ExactPublicationError("Sensor writer cannot close with unresolved exact rows")
            self._closed = True
            self._close_state = "closed"
            self._close_thread = None
            self._exact_publication_condition.notify_all()


class SensorMultiplexEmitter(LogEmitter):
    """Base class for network sensor emitters with per-sensor directory routing.

    Subclasses implement:
    - _render_event(): Convert event data dict to NDJSON string
    - can_handle(): Filter canonical occurrences by type + required contexts
    - emit(): Extract fields from CanonicalOccurrence and call emit_to_sensors()
    """

    _log_filename: str = "output.json"  # Override in subclasses (e.g., "conn.json")
    _flat_filename: str = ""  # Used only for explicit direct-file mode.
    _supported_types: set[str] = set()
    _sort_before_flush: bool = True
    _external_sorting: bool = True
    _include_sensor_identity: bool = False

    def __init__(
        self,
        format_def: FormatDefinition,
        output_path: Path,
        buffer_size: int = 10000,
        threaded: bool = False,
        sensor_hostnames: list[str] | None = None,
    ):
        # If no sensor_hostnames provided AND output_path has a file extension,
        # treat it as a direct file path (backward compat for tests and simple usage)
        self._direct_file_mode = not sensor_hostnames and output_path.suffix != ""
        self._base_dir = output_path.parent if self._direct_file_mode else output_path
        self._direct_file_path = output_path if self._direct_file_mode else None
        self._sensor_hostnames = sensor_hostnames or []
        self._writers: dict[str, _SingleZeekWriter] = {}
        self._writers_lock = Lock()
        self._buffer_size = buffer_size
        super().__init__(format_def, output_path, buffer_size, threaded)

    def _safe_writer_key(self, sensor_hostname: str) -> str:
        """Return the writer key for a routed sensor value."""
        return sanitize_path_component(sensor_hostname)

    def _writer_path_for_key(self, safe_writer_key: str) -> Path:
        """Return the output path for a writer key."""
        if safe_writer_key:
            return self._base_dir / safe_writer_key / self._log_filename
        if self._direct_file_path:
            # Direct file mode (test/simple usage): output_path was a file
            return self._direct_file_path
        # Directory-mode sensor emitters require a sensor. This fallback is
        # retained only as a defensive path and should not be reached by normal
        # generation.
        flat_name = self._flat_filename or self._log_filename
        return self._base_dir / flat_name

    def _get_writer(self, sensor_hostname: str) -> _SingleZeekWriter:
        safe_sensor = self._safe_writer_key(sensor_hostname)
        writer = self._writers.get(safe_sensor)
        if writer is not None:
            return writer
        with self._writers_lock:
            writer = self._writers.get(safe_sensor)
            if writer is not None:
                return writer
            path = self._writer_path_for_key(safe_sensor)
            writer = _SingleZeekWriter(
                path,
                self._buffer_size,
                sort_before_flush=self._sort_before_flush,
                sort_key=getattr(self, "_sort_key_func", self._sort_key_func),
                external_sorting=self._external_sorting,
                checkpoint_mode=self._incremental_checkpointing,
                defer_publication=self._defer_sorted_publication,
            )
            self._writers[safe_sensor] = writer
            logger.debug(f"Created Zeek writer: {path}")
            return writer

    def _get_default_writer(self) -> _SingleZeekWriter:
        """Get the explicit direct-file writer."""
        return self._get_writer("")

    def emit_to_sensors(self, rendered: str, sensor_hostnames: list[str] | None = None) -> None:
        """Route a rendered NDJSON line to the appropriate sensor writers.

        Args:
            rendered: Pre-rendered NDJSON line
            sensor_hostnames: List of sensor hostnames to write to.
                If None/empty, writes to all configured sensors. Directory-mode
                generation drops sensor records when no sensor exists.
        """
        targets = sensor_hostnames if sensor_hostnames else self._sensor_hostnames
        if not targets:
            if not self._direct_file_path:
                return
            self._get_default_writer().write(rendered)
            return
        for hostname in targets:
            self._get_writer(hostname).write(rendered)

    def emit_event(self, event_data: dict[str, Any]) -> None:
        """Route to threaded or non-threaded path."""
        if self.threaded:
            self._emit_threaded(event_data)
        else:
            self._begin_queue_admission(allow_exact=True)
            try:
                self._dispatch(deepcopy(event_data))
            finally:
                self._finish_queue_admission()

    @staticmethod
    def _offset_timestamp(ts: datetime | int | float, milliseconds: int) -> datetime | float:
        """Return a Zeek timestamp shifted by a small analyzer-stage delay."""
        if isinstance(ts, datetime):
            return ts + timedelta(milliseconds=milliseconds)
        return float(ts) + milliseconds / 1000

    def _sensor_metadata(
        self,
        event: Any,
        format_name: str,
        *,
        analyzer_file_id: str | None = None,
    ) -> dict[str, Any]:
        """Return preplanned sensor routing and observation metadata.

        File-dependent analyzer rows are visible only where the owning sensor
        captured enough of that file for its analyzer to run.
        """

        observations = {
            observation.sensor_identity: observation
            for observation in getattr(event, "network_observations", ())
            if format_name in observation.visible_formats
            and (
                analyzer_file_id is None
                or (
                    (file_observation := observation.file_observation(analyzer_file_id)) is not None
                    and file_observation.analyzers_visible
                )
            )
        }
        targets = list(observations)
        observations_planned = getattr(event, "network_observations_planned", False)
        if not targets and not observations_planned:
            targets = event._sensor_hostnames_by_format.get(format_name, [])
        canonical_start = None
        if event.network is not None:
            canonical_start = event.network.started_at
        return {
            "_sensor_hostnames": targets,
            "_network_sensor_observations": observations,
            "_network_observations_planned": observations_planned,
            "_canonical_network_start": canonical_start,
        }

    def _apply_sensor_observation(
        self,
        render_data: dict[str, Any],
        observation: NetworkSensorObservation,
        canonical_start: datetime | None,
        source_timing_key: str | None = None,
        source_duration_key: str | None = None,
        source_duration_field: str = "duration",
    ) -> None:
        """Project a frozen observation into source-native Zeek fields."""

        self._require_frozen_source_keys(
            observation,
            source_timing_key=source_timing_key,
            source_duration_key=source_duration_key,
        )
        render_data["_sensor_traffic_observed"] = True

        original_src_ip = render_data.get("id.orig_h") or render_data.get("_id.orig_h")
        original_dst_ip = render_data.get("id.resp_h") or render_data.get("_id.resp_h")
        tuple_view = observation.tuple_view
        is_icmp = render_data.get("proto") == "icmp"
        if "id.orig_h" in render_data:
            render_data["id.orig_h"] = tuple_view.src_ip
        if "id.orig_p" in render_data and not is_icmp:
            render_data["id.orig_p"] = tuple_view.src_port
        if "id.resp_h" in render_data:
            render_data["id.resp_h"] = tuple_view.dst_ip
        if "id.resp_p" in render_data and not is_icmp:
            render_data["id.resp_p"] = tuple_view.dst_port
        for field, value in {
            "src_ip": tuple_view.src_ip,
            "src_port": tuple_view.src_port,
            "dst_ip": tuple_view.dst_ip,
            "dst_port": tuple_view.dst_port,
            "protocol": tuple_view.protocol,
        }.items():
            if field in render_data:
                render_data[field] = value
        if "local_orig" in render_data:
            render_data["local_orig"] = observation.local_orig
        if "local_resp" in render_data:
            render_data["local_resp"] = observation.local_resp
        if "tx_hosts" in render_data:
            render_data["tx_hosts"] = _swap_host_list_value(
                render_data.get("tx_hosts"),
                original_src_ip,
                tuple_view.src_ip,
            )
            render_data["tx_hosts"] = _swap_host_list_value(
                render_data.get("tx_hosts"),
                original_dst_ip,
                tuple_view.dst_ip,
            )
        if "rx_hosts" in render_data:
            render_data["rx_hosts"] = _swap_host_list_value(
                render_data.get("rx_hosts"),
                original_src_ip,
                tuple_view.src_ip,
            )
            render_data["rx_hosts"] = _swap_host_list_value(
                render_data.get("rx_hosts"),
                original_dst_ip,
                tuple_view.dst_ip,
            )

        timestamp_field = "ts" if "ts" in render_data else "timestamp"
        ts = render_data.get(timestamp_field)
        frozen_source_time = (
            observation.source_time(source_timing_key) if source_timing_key is not None else None
        )
        if frozen_source_time is not None:
            projected_ts: datetime | float = frozen_source_time
        elif canonical_start is not None and isinstance(ts, datetime):
            projected_ts: datetime | float = observation.observed_start_time + (
                ts - canonical_start
            )
        elif canonical_start is not None and isinstance(ts, (int, float)):
            projected_ts = (
                observation.observed_start_time.timestamp()
                + float(ts)
                - canonical_start.timestamp()
            )
        else:
            projected_ts = ts
        # TODO(v2-timing): unmigrated Zeek formats still use the legacy relative
        # projection adapter. Migrated rows carry a frozen source timing key and
        # bypass every emitter-side bound repair.
        if source_timing_key is None:
            if isinstance(projected_ts, datetime):
                projected_ts = max(projected_ts, observation.observed_start_time)
                if observation.observed_close_time is not None:
                    projected_ts = min(projected_ts, observation.observed_close_time)
            elif isinstance(projected_ts, (int, float)):
                projected_ts = max(projected_ts, observation.observed_start_time.timestamp())
                if observation.observed_close_time is not None:
                    projected_ts = min(projected_ts, observation.observed_close_time.timestamp())
        if projected_ts is not None:
            render_data[timestamp_field] = projected_ts

        frozen_duration = (
            observation.source_duration(source_duration_key)
            if source_duration_key is not None
            else None
        )
        if frozen_duration is not None:
            render_data[source_duration_field] = frozen_duration
        elif (
            source_timing_key is None
            and self.format_def.name != "zeek_conn"
            and observation.observed_close_time is not None
        ):
            remaining_seconds = None
            if isinstance(projected_ts, datetime):
                remaining_seconds = max(
                    0.0,
                    (observation.observed_close_time - projected_ts).total_seconds(),
                )
            elif isinstance(projected_ts, (int, float)):
                remaining_seconds = max(
                    0.0,
                    observation.observed_close_time.timestamp() - float(projected_ts),
                )
            if remaining_seconds is not None:
                for interval_field in ("duration", "rtt"):
                    interval = render_data.get(interval_field)
                    if isinstance(interval, (int, float)):
                        render_data[interval_field] = min(
                            max(0.0, float(interval)),
                            remaining_seconds,
                        )

        if self.format_def.name == "zeek_conn":
            ledger = observation.traffic
            render_data.update(
                {
                    "duration": (
                        frozen_duration
                        if source_duration_key is not None
                        else observation.observed_duration
                    ),
                    "orig_bytes": ledger.orig.payload_bytes,
                    "resp_bytes": ledger.resp.payload_bytes,
                    "orig_pkts": ledger.orig.packets,
                    "resp_pkts": ledger.resp.packets,
                    "orig_ip_bytes": ledger.orig.ip_bytes,
                    "resp_ip_bytes": ledger.resp.ip_bytes,
                    "missed_bytes": ledger.missed_bytes,
                    "history": observation.history,
                }
            )
        elif self.format_def.name == "zeek_http":
            if observation.http_request_body_len is not None:
                render_data["request_body_len"] = observation.http_request_body_len
            if observation.http_response_body_len is not None:
                render_data["response_body_len"] = observation.http_response_body_len

        original_file_id = render_data.get("fuid") or render_data.get("id")
        if isinstance(original_file_id, str):
            file_observation = observation.file_observation(original_file_id)
            if file_observation is not None and self.format_def.name == "zeek_files":
                render_data["seen_bytes"] = file_observation.seen_bytes
                render_data["total_bytes"] = file_observation.total_bytes
                render_data["missing_bytes"] = file_observation.missing_bytes
                if not file_observation.analyzers_visible:
                    render_data["analyzers"] = None
                    for hash_field in ("md5", "sha1", "sha256"):
                        render_data[hash_field] = None

        original_uid = render_data.get("uid")
        if isinstance(original_uid, str):
            render_data["uid"] = observation.connection_id(original_uid)
        for uid_list_field in ("uids", "conn_uids"):
            uid_values = render_data.get(uid_list_field)
            if isinstance(uid_values, list):
                render_data[uid_list_field] = [
                    observation.connection_id(uid) if isinstance(uid, str) else uid
                    for uid in uid_values
                ]
        for fuid_field in ("id", "fuid"):
            original_fuid = render_data.get(fuid_field)
            if isinstance(original_fuid, str):
                render_data[fuid_field] = observation.file_id(original_fuid)
        for fuid_list_field in ("cert_chain_fuids", "orig_fuids", "resp_fuids", "fuids"):
            fuid_values = render_data.get(fuid_list_field)
            if isinstance(fuid_values, (list, tuple)):
                if fuid_list_field == "cert_chain_fuids":
                    fuid_values = [
                        fuid
                        for fuid in fuid_values
                        if not isinstance(fuid, str)
                        or (
                            (file_observation := observation.file_observation(fuid)) is not None
                            and file_observation.analyzers_visible
                        )
                    ]
                projected_fuids = [
                    observation.file_id(fuid) if isinstance(fuid, str) else fuid
                    for fuid in fuid_values
                ]
                render_data[fuid_list_field] = (
                    projected_fuids
                    if projected_fuids or fuid_list_field != "cert_chain_fuids"
                    else None
                )

    def _require_frozen_source_keys(
        self,
        observation: NetworkSensorObservation,
        *,
        source_timing_key: str | None,
        source_duration_key: str | None,
    ) -> None:
        """Fail before rendering when a migrated row lacks its frozen timing contract."""

        missing: list[str] = []
        if source_timing_key is not None and observation.source_time(source_timing_key) is None:
            missing.append(f"timestamp {source_timing_key!r}")
        if (
            source_duration_key is not None
            and observation.source_duration(source_duration_key) is None
        ):
            missing.append(f"duration {source_duration_key!r}")
        if missing:
            raise EventContractError(
                f"{self.format_def.name} observation {observation.sensor_identity!r} "
                f"is missing frozen source {' and '.join(missing)}"
            )

    def _dispatch(self, event_data: dict[str, Any]) -> None:
        """Render and route to sensor writers.

        Sensor-local tuple, timing, traffic, and identifiers are consumed from
        frozen observation plans. The emitter performs no sensor synthesis.
        Skips events where _render_event returns None (e.g., SnortEmitter
        filters out non-IDS connection events).
        """
        sensor_hostnames = event_data.pop("_sensor_hostnames", None)
        observations = event_data.pop("_network_sensor_observations", {})
        observations_planned = event_data.pop("_network_observations_planned", False)
        canonical_start = event_data.pop("_canonical_network_start", None)
        source_timing_key = event_data.pop("_source_timing_key", None)
        source_duration_key = event_data.pop("_source_duration_key", None)
        source_duration_field = event_data.pop("_source_duration_field", "duration")
        event_data.pop("_allow_sensor_observation_variance", None)
        targets = (
            sensor_hostnames if observations_planned else sensor_hostnames or self._sensor_hostnames
        )

        for hostname in targets or ():
            observation = observations.get(hostname)
            if observation is not None:
                self._require_frozen_source_keys(
                    observation,
                    source_timing_key=source_timing_key,
                    source_duration_key=source_duration_key,
                )

        if not targets:
            if observations_planned:
                return
            if not self._direct_file_path:
                return
            _enforce_http_body_invariants(event_data)
            _enforce_ip_byte_invariants(event_data)
            if self._include_sensor_identity:
                event_data["_sensor_identity"] = "__direct__"
            rendered = self._render_event(event_data)
            if rendered is None:
                return
            self.emit_to_sensors(rendered, sensor_hostnames)
        else:
            for hostname in targets:
                render_data = dict(event_data)
                if self._include_sensor_identity:
                    render_data["_sensor_identity"] = hostname
                observation = observations.get(hostname)
                if observation is not None:
                    self._apply_sensor_observation(
                        render_data,
                        observation,
                        canonical_start,
                        source_timing_key,
                        source_duration_key,
                        source_duration_field,
                    )
                _enforce_http_body_invariants(render_data)
                _enforce_ip_byte_invariants(render_data)
                rendered = self._render_event(render_data)
                if rendered is None:
                    continue
                self._get_writer(hostname).write(rendered)

    def _render_zeek_json(self, event_data: dict[str, Any]) -> str:
        """Common Zeek NDJSON rendering: timestamp conversion, dotted fields, compact JSON.

        Subclasses can call this for standard Zeek JSON rendering, or override
        _render_event() entirely for custom behavior.
        """
        # Convert timestamp to epoch float with microsecond precision
        if "ts" in event_data:
            ts = event_data["ts"]
            if isinstance(ts, datetime):
                event_data["ts"] = round(ts.timestamp(), 6)
            elif isinstance(ts, str):
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                event_data["ts"] = round(dt.timestamp(), 6)

        # Handle dotted field names (id.orig_h → data dict for template)
        data_fields = {}
        regular_fields = {}
        for key, value in event_data.items():
            if key.startswith("_"):
                continue  # Skip internal metadata fields
            if "." in key:
                data_fields[key] = value
            else:
                regular_fields[key] = value

        template_context = regular_fields.copy()
        if data_fields:
            template_context["data"] = data_fields

        # Render Jinja2 template and compact to NDJSON
        rendered = self._template.render(**template_context)
        try:
            data = json.loads(rendered)
            data = _normalize_zeek_float_precision(data)
            return json.dumps(data, separators=(",", ":"))
        except json.JSONDecodeError:
            return rendered.strip()

    @staticmethod
    def _sort_key_func(line: str) -> tuple[float, str]:
        """Sort Zeek NDJSON by `ts`, with malformed lines last and stable tie-breaking."""
        try:
            data = json.loads(line)
            ts = data.get("ts")
            if isinstance(ts, int | float):
                return (float(ts), line)
        except json.JSONDecodeError:
            pass
        return (float("inf"), line)

    def _run(self) -> None:
        """Thread run loop — dispatch events to per-sensor writers."""
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
                except Exception as exc:  # noqa: BLE001
                    self._thread_error = exc
                    logger.exception(
                        "Unhandled exception in %s emitter thread; stopping thread",
                        self.format_def.name,
                    )
                    self._stop_event.set()
                finally:
                    self._event_queue.task_done()
            except Empty:
                continue
        self.flush()
        logger.debug(f"Emitter thread stopped for {self.format_def.name}")

    def flush(self) -> None:
        """Flush all sensor writers."""
        self._wait_for_exact_publication_turn(None)
        with self._writers_lock:
            for writer in self._writers.values():
                writer.flush()

    def _buffer_event(self, rendered: str) -> None:
        """Override base class _buffer_event to route through multiplexer."""
        self._get_default_writer().write(rendered)

    def _flush_unlocked(self) -> None:
        """Override to prevent base class from writing to single output_path."""
        pass

    def close(self) -> None:
        """Close emitter and flush all sensor writers."""
        if not self._begin_close():
            return
        thread_failure: RuntimeError | None = None
        if self.threaded:
            try:
                self.stop_thread()
                self._raise_if_thread_failed()
            except RuntimeError as exc:
                thread_failure = exc
        writer_failure: OSError | RuntimeError | None = None
        with self._writers_lock:
            for writer in self._writers.values():
                try:
                    writer.close()
                except (OSError, RuntimeError) as exc:
                    if writer_failure is None:
                        writer_failure = exc
        if thread_failure is not None:
            if writer_failure is not None:
                thread_failure.add_note(f"Writer cleanup also failed: {writer_failure}")
                self._fail_close()
            else:
                self._finish_close()
            raise thread_failure
        if writer_failure is not None:
            self._fail_close()
            raise writer_failure
        self._finish_close()

    @property
    def event_count(self) -> int:
        """Total events across all sensor writers."""
        return sum(w.event_count for w in self._writers.values())

    @event_count.setter
    def event_count(self, value: int) -> None:
        # Base class sets this to 0 in __init__; ignore it
        pass
