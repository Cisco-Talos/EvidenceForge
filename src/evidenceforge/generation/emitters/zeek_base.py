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

When no sensors are configured (backward compat), writes directly to:
    base_dir/<log_filename>
"""

import json
import logging
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from queue import Empty
from threading import Lock
from typing import Any

from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.base import LogEmitter
from evidenceforge.utils.paths import sanitize_path_component
from evidenceforge.utils.rng import _stable_seed

logger = logging.getLogger(__name__)


def _swap_host_list_value(value: Any, original_ip: Any, visible_ip: Any) -> Any:
    """Apply a per-sensor NAT IP view to Zeek list-valued host fields."""
    if (
        not isinstance(value, list)
        or not isinstance(original_ip, str)
        or not isinstance(visible_ip, str)
    ):
        return value
    return [visible_ip if item == original_ip else item for item in value]


def _sensor_variation_fraction(hostname: str, uid: Any, field: str, magnitude: float) -> float:
    """Return a deterministic signed per-sensor observation variation."""
    seed = _stable_seed(f"zeek_sensor_observation:{hostname}:{uid}:{field}")
    # Deterministic fraction in [-magnitude, +magnitude], avoiding an exact zero.
    centered = ((seed % 2001) - 1000) / 1000.0
    if centered == 0:
        centered = 0.137
    return centered * magnitude


def _sensor_clock_skew_us(hostname: str) -> int:
    """Return stable per-sensor clock skew in microseconds."""
    seed = _stable_seed(f"zeek_sensor_clock_skew:{hostname}")
    return (seed % 800_001) - 400_000


def _sensor_path_delay_us(hostname: str, original_uid: Any) -> int:
    """Return per-flow capture timestamp variance for a sensor observation."""
    seed = _stable_seed(f"zeek_sensor_path_delay:{hostname}:{original_uid}")
    # Tap placement, NIC timestamping, Zeek scheduling, and capture buffering
    # all add small positive path delay. The stable per-sensor clock skew owns
    # the sign of cross-sensor offsets, so identical paths do not flip earlier
    # and later flow-by-flow like independent synthetic jitter.
    return 5_000 + (seed % 75_001)


def _jitter_numeric_observation(
    render_data: dict[str, Any],
    field: str,
    hostname: str,
    uid: Any,
    magnitude: float,
    *,
    minimum: int | float = 0,
) -> None:
    """Apply deterministic per-sensor jitter to numeric Zeek observation fields."""
    value = render_data.get(field)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return
    if value <= 0:
        return
    fraction = _sensor_variation_fraction(hostname, uid, field, magnitude)
    varied = value * (1.0 + fraction)
    if isinstance(value, int):
        varied = int(round(varied))
    render_data[field] = max(type(value)(minimum), type(value)(varied))


def _apply_sensor_observation_variance(
    render_data: dict[str, Any],
    hostname: str,
    original_uid: Any,
) -> None:
    """Make multi-sensor Zeek rows look like independent tap observations.

    The canonical event still owns the true connection tuple and protocol
    facts. This only models source-native observation differences from packet
    loss, snaplen, tap placement, and analyzer cutoffs.
    """
    clone_fields = (
        "duration",
        "orig_bytes",
        "resp_bytes",
        "orig_pkts",
        "resp_pkts",
        "orig_ip_bytes",
        "resp_ip_bytes",
    )
    original_observation = {field: render_data.get(field) for field in clone_fields}
    # A downstream/DMZ tap may account for a few bytes Zeek could not attribute
    # cleanly. Keep this sparse and small so it reads as capture imperfection.
    added_missed_bytes = False
    if "missed_bytes" in render_data:
        missed = render_data.get("missed_bytes") or 0
        if isinstance(missed, int):
            seed = _stable_seed(f"zeek_sensor_missed:{hostname}:{original_uid}")
            if seed % 11 == 0:
                render_data["missed_bytes"] = missed + 16 + (seed % 496)
                added_missed_bytes = True
    if added_missed_bytes:
        for field in ("orig_pkts", "resp_pkts"):
            _jitter_numeric_observation(
                render_data,
                field,
                hostname,
                original_uid,
                0.018,
                minimum=1,
            )
    if not render_data.get("_lock_duration"):
        _jitter_numeric_observation(render_data, "duration", hostname, original_uid, 0.027)
    for field in ("orig_pkts", "resp_pkts"):
        _jitter_numeric_observation(render_data, field, hostname, original_uid, 0.035, minimum=1)
    if render_data.get("_http_request_body_len") is None:
        _jitter_numeric_observation(
            render_data,
            "orig_bytes",
            hostname,
            original_uid,
            0.012,
            minimum=0,
        )
    if render_data.get("_http_response_body_len") is None:
        _jitter_numeric_observation(
            render_data,
            "resp_bytes",
            hostname,
            original_uid,
            0.012,
            minimum=0,
        )
    for field in ("orig_ip_bytes", "resp_ip_bytes"):
        _jitter_numeric_observation(
            render_data,
            field,
            hostname,
            original_uid,
            0.024,
            minimum=0,
        )
    if all(render_data.get(field) == original_observation[field] for field in clone_fields):
        duration = render_data.get("duration")
        if (
            not render_data.get("_lock_duration")
            and isinstance(duration, (int, float))
            and not isinstance(duration, bool)
            and duration > 0
        ):
            seed = _stable_seed(f"zeek_sensor_duration_floor:{hostname}:{original_uid}")
            direction = -1 if seed % 2 else 1
            delta = max(duration * 0.0075, 0.000001)
            render_data["duration"] = max(0.000001, duration + (direction * delta))
        else:
            proto = str(render_data.get("proto") or "").lower()
            max_header_bytes = {"udp": 68}.get(proto)
            seed = _stable_seed(f"zeek_sensor_ip_byte_floor:{hostname}:{original_uid}")
            sides = ("resp", "orig") if seed % 2 else ("orig", "resp")
            for side in sides:
                payload = render_data.get(f"{side}_bytes")
                packets = render_data.get(f"{side}_pkts")
                ip_bytes = render_data.get(f"{side}_ip_bytes")
                if not all(isinstance(value, int) for value in (payload, packets, ip_bytes)):
                    continue
                if packets <= 0 or ip_bytes < 0:
                    continue
                if max_header_bytes is not None:
                    maximum_ip_bytes = payload + (max_header_bytes * packets)
                    if ip_bytes >= maximum_ip_bytes:
                        continue
                render_data[f"{side}_ip_bytes"] = ip_bytes + 1
                break
    _enforce_http_body_invariants(render_data)
    _enforce_ip_byte_invariants(render_data)


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
    """Keep Zeek IP-byte counters physically possible after observation jitter."""
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
    _flat_filename: str = ""  # Override for backward-compat flat output (e.g., "zeek_conn.json")
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

    def _get_writer(self, sensor_hostname: str) -> _SingleZeekWriter:
        safe_sensor = sanitize_path_component(sensor_hostname)
        writer = self._writers.get(safe_sensor)
        if writer is not None:
            return writer
        with self._writers_lock:
            writer = self._writers.get(safe_sensor)
            if writer is not None:
                return writer
            if safe_sensor:
                path = self._base_dir / safe_sensor / self._log_filename
            elif self._direct_file_path:
                # Direct file mode (test/simple usage): output_path was a file
                path = self._direct_file_path
            else:
                # No sensors configured → flat output using format name
                flat_name = self._flat_filename or self._log_filename
                path = self._base_dir / flat_name
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
        """Get the backward-compat flat writer (no sensor subdirectory)."""
        return self._get_writer("")

    def emit_to_sensors(self, rendered: str, sensor_hostnames: list[str] | None = None) -> None:
        """Route a rendered NDJSON line to the appropriate sensor writers.

        Args:
            rendered: Pre-rendered NDJSON line
            sensor_hostnames: List of sensor hostnames to write to.
                If None/empty, writes to all configured sensors (or flat output).
        """
        targets = sensor_hostnames if sensor_hostnames else self._sensor_hostnames
        if not targets:
            # No sensors configured → backward compat flat output
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

    @staticmethod
    def _derive_sensor_uid(original_uid: str, sensor_hostname: str) -> str:
        """Derive a deterministic per-sensor UID from the original UID.

        All emitters processing the same event for the same sensor will derive
        the same UID, preserving cross-log correlation (conn↔dns↔http↔ssl)
        within a sensor. Different sensors get different UIDs.

        Uses HMAC-like hashing to produce a base62 UID of the same length
        and prefix as the original.
        """
        import hashlib
        import string

        base62 = string.ascii_uppercase + string.ascii_lowercase + string.digits
        prefix = original_uid[0] if original_uid else "C"
        target_len = len(original_uid) - 1  # Exclude prefix

        from evidenceforge.utils.ids import _has_synthetic_marker

        for counter in range(16):
            suffix = "" if counter == 0 else f":{counter}"
            h = hashlib.sha256(f"{original_uid}:{sensor_hostname}{suffix}".encode()).digest()
            chars = []
            for byte in h[:target_len]:
                chars.append(base62[byte % 62])
            derived_uid = prefix + "".join(chars)
            if not _has_synthetic_marker(derived_uid):
                return derived_uid
        return derived_uid

    @classmethod
    def _derive_sensor_file_id(cls, original_id: str, sensor_hostname: str) -> str:
        """Derive a deterministic per-sensor Zeek FUID-style identifier."""
        if not original_id:
            return original_id
        return cls._derive_sensor_uid(original_id, sensor_hostname)

    def _dispatch(self, event_data: dict[str, Any]) -> None:
        """Render and route to sensor writers.

        When multiple sensors observe the same connection, each sensor gets a
        deterministic unique Zeek UID derived from hash(original_uid, sensor).
        All emitters for the same event+sensor produce the same derived UID,
        preserving cross-log correlation within each sensor.
        Skips events where _render_event returns None (e.g., SnortEmitter
        filters out non-IDS connection events).
        """
        sensor_hostnames = event_data.pop("_sensor_hostnames", None)
        nat_swaps = event_data.pop("_nat_swaps_by_sensor", None)
        targets = sensor_hostnames if sensor_hostnames else self._sensor_hostnames

        if not targets:
            # No sensor targets: render once to the flat output.
            _enforce_http_body_invariants(event_data)
            _enforce_ip_byte_invariants(event_data)
            rendered = self._render_event(event_data)
            if rendered is None:
                return
            self.emit_to_sensors(rendered, sensor_hostnames)
        else:
            # Multiple sensors: each gets a deterministic unique UID
            # and potentially NAT-swapped IPs
            original_uid = event_data.get("uid")
            if not original_uid:
                for uid_list_field in ("conn_uids", "uids"):
                    uid_values = event_data.get(uid_list_field)
                    if isinstance(uid_values, list):
                        original_uid = next(
                            (
                                uid
                                for uid in uid_values
                                if isinstance(uid, str) and uid.startswith("C")
                            ),
                            None,
                        )
                    if original_uid:
                        break
            for i, hostname in enumerate(targets):
                # Always copy before per-sensor timing and identifier derivation.
                render_data = dict(event_data)
                # Apply NAT IP swaps for post-NAT sensors
                if nat_swaps and hostname in nat_swaps:
                    if render_data is event_data:
                        render_data = dict(event_data)
                    swaps = nat_swaps[hostname]
                    if "src_ip" in swaps:
                        render_data["id.orig_h"] = swaps["src_ip"]
                    if "src_port" in swaps:
                        render_data["id.orig_p"] = swaps["src_port"]
                    if "dst_ip" in swaps:
                        render_data["id.resp_h"] = swaps["dst_ip"]
                    if "dst_port" in swaps:
                        render_data["id.resp_p"] = swaps["dst_port"]
                    if "local_orig" in swaps:
                        render_data["local_orig"] = swaps["local_orig"]
                    if "local_resp" in swaps:
                        render_data["local_resp"] = swaps["local_resp"]
                    if "src_ip" in swaps:
                        original_src_ip = event_data.get("id.orig_h") or event_data.get(
                            "_id.orig_h"
                        )
                        render_data["tx_hosts"] = _swap_host_list_value(
                            render_data.get("tx_hosts"),
                            original_src_ip,
                            swaps["src_ip"],
                        )
                        render_data["rx_hosts"] = _swap_host_list_value(
                            render_data.get("rx_hosts"),
                            original_src_ip,
                            swaps["src_ip"],
                        )
                    if "dst_ip" in swaps:
                        original_dst_ip = event_data.get("id.resp_h") or event_data.get(
                            "_id.resp_h"
                        )
                        render_data["tx_hosts"] = _swap_host_list_value(
                            render_data.get("tx_hosts"),
                            original_dst_ip,
                            swaps["dst_ip"],
                        )
                        render_data["rx_hosts"] = _swap_host_list_value(
                            render_data.get("rx_hosts"),
                            original_dst_ip,
                            swaps["dst_ip"],
                        )
                # Sensors have stable clock skew plus per-flow capture timing
                # variance. Keep the offset shared across Zeek log families for
                # a flow, but avoid a fixed cross-sensor clone delay.
                if i > 0:
                    sensor_delay_us = _sensor_clock_skew_us(hostname) + _sensor_path_delay_us(
                        hostname, original_uid
                    )
                    ts = render_data.get("ts")
                    if ts is not None:
                        if isinstance(ts, datetime):
                            render_data["ts"] = ts + timedelta(microseconds=sensor_delay_us)
                        elif isinstance(ts, (int, float)):
                            render_data["ts"] = ts + sensor_delay_us / 1_000_000
                    if render_data.get("_allow_sensor_observation_variance"):
                        _apply_sensor_observation_variance(render_data, hostname, original_uid)
                _enforce_http_body_invariants(render_data)
                _enforce_ip_byte_invariants(render_data)
                if original_uid:
                    # Derive a deterministic UID for this sensor
                    render_data["uid"] = self._derive_sensor_uid(original_uid, hostname)
                for uid_list_field in ("uids", "conn_uids"):
                    uid_values = render_data.get(uid_list_field)
                    if not isinstance(uid_values, list):
                        continue
                    render_data[uid_list_field] = [
                        self._derive_sensor_uid(uid, hostname)
                        if isinstance(uid, str) and uid.startswith("C")
                        else uid
                        for uid in uid_values
                    ]
                for fuid_field in ("id", "fuid"):
                    original_fuid = render_data.get(fuid_field)
                    if isinstance(original_fuid, str) and original_fuid.startswith("F"):
                        render_data[fuid_field] = self._derive_sensor_file_id(
                            original_fuid, hostname
                        )
                for fuid_list_field in ("cert_chain_fuids", "resp_fuids"):
                    fuid_values = render_data.get(fuid_list_field)
                    if isinstance(fuid_values, list):
                        render_data[fuid_list_field] = [
                            self._derive_sensor_file_id(fuid, hostname)
                            if isinstance(fuid, str) and fuid.startswith("F")
                            else fuid
                            for fuid in fuid_values
                        ]
                rendered = self._render_event(render_data)
                if rendered is None:
                    return
                self._get_writer(hostname).write(rendered)
            # Restore original UID so downstream code isn't affected
            if original_uid:
                event_data["uid"] = original_uid

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
            # Round timestamp to 6 decimal places (Zeek standard)
            if "ts" in data and isinstance(data["ts"], float):
                data["ts"] = round(data["ts"], 6)
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
