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
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from queue import Empty
from threading import Lock
from typing import Any

from evidenceforge.events.network import NetworkSensorObservation
from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.base import LogEmitter
from evidenceforge.utils.paths import sanitize_path_component

logger = logging.getLogger(__name__)


def zeek_format_observed(event: Any, format_name: str) -> bool:
    """Return whether a Zeek sibling format survived source observation.

    Direct emitter tests and low-level callers do not run through the dispatcher,
    so an empty observed-format set means "unknown" rather than "dropped".
    """
    observed_formats = getattr(event, "_observed_formats", set())
    return not observed_formats or format_name in observed_formats


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
    ):
        self.output_path = output_path
        self.buffer: list[str] = []
        self.buffer_size = buffer_size
        self.event_count = 0
        self._lock = Lock()
        self._sort_before_flush = sort_before_flush
        self._sort_key = sort_key

    def write(self, rendered: str) -> None:
        with self._lock:
            self.buffer.append(rendered)
            self.event_count += 1
            if len(self.buffer) >= self.buffer_size:
                self._flush_unlocked()

    def flush(self) -> None:
        with self._lock:
            self._flush_unlocked()

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
        """Flush pending lines and sort the complete NDJSON file by timestamp."""
        with self._lock:
            self._flush_unlocked()
            if not self._sort_before_flush or not self.output_path.exists():
                return
            lines = [line for line in self.output_path.read_text(encoding="utf-8").splitlines()]
            if not lines:
                return
            if self._sort_key:
                lines.sort(key=self._sort_key)
            else:
                lines.sort()
            with open(self.output_path, "w", encoding="utf-8") as f:
                for line in lines:
                    f.write(line)
                    f.write("\n")


class SensorMultiplexEmitter(LogEmitter):
    """Base class for network sensor emitters with per-sensor directory routing.

    Subclasses implement:
    - _render_event(): Convert event data dict to NDJSON string
    - can_handle(): Filter SecurityEvents by type + required contexts
    - emit(): Extract fields from SecurityEvent and call emit_to_sensors()
    """

    _log_filename: str = "output.json"  # Override in subclasses (e.g., "conn.json")
    _flat_filename: str = ""  # Used only for explicit direct-file mode.
    _supported_types: set[str] = set()
    _sort_before_flush: bool = True

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
            self._dispatch(event_data)

    @staticmethod
    def _offset_timestamp(ts: datetime | int | float, milliseconds: int) -> datetime | float:
        """Return a Zeek timestamp shifted by a small analyzer-stage delay."""
        if isinstance(ts, datetime):
            return ts + timedelta(milliseconds=milliseconds)
        return float(ts) + milliseconds / 1000

    def _sensor_metadata(self, event: Any, format_name: str) -> dict[str, Any]:
        """Return preplanned sensor routing and observation metadata."""

        observations = {
            observation.sensor_identity: observation
            for observation in getattr(event, "network_observations", ())
            if format_name in observation.visible_formats
        }
        targets = list(observations)
        if not targets:
            targets = event._sensor_hostnames_by_format.get(format_name, [])
        canonical_start = None
        if event.network is not None and event.network.transaction is not None:
            canonical_start = event.network.transaction.started_at
        return {
            "_sensor_hostnames": targets,
            "_network_sensor_observations": observations,
            "_network_observations_planned": getattr(
                event,
                "network_observations_planned",
                False,
            ),
            "_nat_swaps_by_sensor": getattr(event, "_nat_swaps_by_sensor", {}),
            "_canonical_network_start": canonical_start,
        }

    def _apply_sensor_observation(
        self,
        render_data: dict[str, Any],
        observation: NetworkSensorObservation,
        canonical_start: datetime | None,
    ) -> None:
        """Project a frozen observation into source-native Zeek fields."""

        original_src_ip = render_data.get("id.orig_h") or render_data.get("_id.orig_h")
        original_dst_ip = render_data.get("id.resp_h") or render_data.get("_id.resp_h")
        tuple_view = observation.tuple_view
        if "id.orig_h" in render_data:
            render_data["id.orig_h"] = tuple_view.src_ip
        if "id.orig_p" in render_data:
            render_data["id.orig_p"] = tuple_view.src_port
        if "id.resp_h" in render_data:
            render_data["id.resp_h"] = tuple_view.dst_ip
        if "id.resp_p" in render_data:
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
        if canonical_start is not None and isinstance(ts, datetime):
            render_data[timestamp_field] = observation.observed_start_time + (ts - canonical_start)
        elif canonical_start is not None and isinstance(ts, (int, float)):
            render_data[timestamp_field] = (
                observation.observed_start_time.timestamp()
                + float(ts)
                - canonical_start.timestamp()
            )

        if self.format_def.name == "zeek_conn":
            ledger = observation.traffic
            render_data.update(
                {
                    "duration": observation.observed_duration,
                    "orig_bytes": ledger.orig.payload_bytes,
                    "resp_bytes": ledger.resp.payload_bytes,
                    "orig_pkts": ledger.orig.packets,
                    "resp_pkts": ledger.resp.packets,
                    "orig_ip_bytes": ledger.orig.ip_bytes,
                    "resp_ip_bytes": ledger.resp.ip_bytes,
                    "missed_bytes": ledger.missed_bytes,
                }
            )

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
        for fuid_list_field in ("cert_chain_fuids", "resp_fuids", "fuids"):
            fuid_values = render_data.get(fuid_list_field)
            if isinstance(fuid_values, list):
                render_data[fuid_list_field] = [
                    observation.file_id(fuid) if isinstance(fuid, str) else fuid
                    for fuid in fuid_values
                ]

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
        compatibility_nat_swaps = event_data.pop("_nat_swaps_by_sensor", None)
        event_data.pop("_allow_sensor_observation_variance", None)
        targets = (
            sensor_hostnames if observations_planned else sensor_hostnames or self._sensor_hostnames
        )

        if not targets:
            if observations_planned:
                return
            if not self._direct_file_path:
                return
            _enforce_http_body_invariants(event_data)
            _enforce_ip_byte_invariants(event_data)
            rendered = self._render_event(event_data)
            if rendered is None:
                return
            self.emit_to_sensors(rendered, sensor_hostnames)
        else:
            for hostname in targets:
                render_data = dict(event_data)
                observation = observations.get(hostname)
                if observation is not None:
                    self._apply_sensor_observation(
                        render_data,
                        observation,
                        canonical_start,
                    )
                elif compatibility_nat_swaps and hostname in compatibility_nat_swaps:
                    swaps = compatibility_nat_swaps[hostname]
                    original_src_ip = render_data.get(
                        "id.orig_h",
                        render_data.get("_id.orig_h"),
                    )
                    original_dst_ip = render_data.get(
                        "id.resp_h",
                        render_data.get("_id.resp_h"),
                    )
                    for field, rendered_field in {
                        "src_ip": "id.orig_h",
                        "src_port": "id.orig_p",
                        "dst_ip": "id.resp_h",
                        "dst_port": "id.resp_p",
                        "local_orig": "local_orig",
                        "local_resp": "local_resp",
                    }.items():
                        if field in swaps and (
                            not field.startswith("local_") or rendered_field in render_data
                        ):
                            internal_field = f"_{rendered_field}"
                            target_field = (
                                internal_field if internal_field in render_data else rendered_field
                            )
                            render_data[target_field] = swaps[field]
                    for hosts_field in ("tx_hosts", "rx_hosts"):
                        if hosts_field not in render_data:
                            continue
                        render_data[hosts_field] = _swap_host_list_value(
                            render_data.get(hosts_field),
                            original_src_ip,
                            swaps.get("src_ip"),
                        )
                        render_data[hosts_field] = _swap_host_list_value(
                            render_data.get(hosts_field),
                            original_dst_ip,
                            swaps.get("dst_ip"),
                        )
                _enforce_http_body_invariants(render_data)
                _enforce_ip_byte_invariants(render_data)
                rendered = self._render_event(render_data)
                if rendered is None:
                    return
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
                event_data = self._event_queue.get(timeout=0.1)
                self._dispatch(event_data)
                self._event_queue.task_done()
            except Empty:
                if self._flush_barrier.is_set():
                    self.flush()
                    self._flush_barrier.clear()
        self.flush()
        logger.debug(f"Emitter thread stopped for {self.format_def.name}")

    def flush(self) -> None:
        """Flush all sensor writers."""
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
        if self.threaded:
            self.stop_thread()
        with self._writers_lock:
            for writer in self._writers.values():
                writer.close()

    @property
    def event_count(self) -> int:
        """Total events across all sensor writers."""
        return sum(w.event_count for w in self._writers.values())

    @event_count.setter
    def event_count(self, value: int) -> None:
        # Base class sets this to 0 in __init__; ignore it
        pass
