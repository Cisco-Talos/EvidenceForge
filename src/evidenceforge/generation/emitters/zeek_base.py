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
import math
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from queue import Empty
from threading import Lock
from typing import Any

from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.activity.timing_profiles import network_sensor_observation_timing
from evidenceforge.generation.emitters.base import LogEmitter
from evidenceforge.utils.paths import sanitize_path_component
from evidenceforge.utils.rng import _stable_seed

logger = logging.getLogger(__name__)

_BULK_TCP_FLOW_MIN_IP_BYTES = 10_000_000
_BULK_TCP_FLOW_MISSED_CAP_BYTES = 65_536


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
    timing = network_sensor_observation_timing()
    seed = _stable_seed(f"zeek_sensor_clock_skew:{hostname}")
    width = timing.clock_skew_max_us - timing.clock_skew_min_us + 1
    return timing.clock_skew_min_us + (seed % max(1, width))


def _sensor_clock_drift_us(hostname: str, ts: Any) -> int:
    """Return small time-bucketed clock drift for a sensor timestamp."""
    if isinstance(ts, datetime):
        epoch_seconds = int(ts.timestamp())
    elif isinstance(ts, (int, float)):
        if not math.isfinite(ts):
            return 0
        epoch_seconds = int(ts)
    else:
        epoch_seconds = 0
    # Drift moves slowly, not per packet. Fifteen-minute buckets are enough to
    # avoid a perfectly fixed offset while keeping well-synced sensors close.
    bucket = epoch_seconds // 900
    seed = _stable_seed(f"zeek_sensor_clock_drift:{hostname}:{bucket}")
    return (seed % 401) - 200


def _sensor_clock_adjustment_us(hostname: str, ts: Any) -> int:
    """Return stable skew plus bounded drift within the configured skew window."""
    timing = network_sensor_observation_timing()
    skew = _sensor_clock_skew_us(hostname) + _sensor_clock_drift_us(hostname, ts)
    return max(timing.clock_skew_min_us, min(timing.clock_skew_max_us, skew))


def _sensor_path_delay_us(hostname: str, original_uid: Any = None) -> int:
    """Return stable capture timestamp delay for a sensor observation."""
    timing = network_sensor_observation_timing()
    seed = _stable_seed(f"zeek_sensor_path_delay:{hostname}")
    # Tap placement, NIC timestamping, Zeek scheduling, and capture buffering
    # add a small positive delay. Keep the baseline stable by sensor, then add
    # bounded flow-local capture texture so repeated Core/DMZ observations do
    # not collapse into a tiny set of exact offsets.
    width = timing.path_delay_max_us - timing.path_delay_min_us + 1
    baseline = timing.path_delay_min_us + (seed % max(1, width))
    if original_uid is None:
        return baseline
    jitter_seed = _stable_seed(f"zeek_sensor_path_delay_jitter:{hostname}:{original_uid}")
    # Flow-local buffering and packet-broker scheduling should sometimes
    # dominate the stable sensor path ordering. Keep each individual sensor
    # inside the configured path-delay window, but allow same-flow cross-sensor
    # deltas to change sign instead of always reading as a fixed tap order.
    jitter_width = max(6_000, int(width * 0.55))
    jitter = (jitter_seed % ((jitter_width * 2) + 1)) - jitter_width
    return max(timing.path_delay_min_us, min(timing.path_delay_max_us, baseline + jitter))


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
    try:
        varied = value * (1.0 + fraction)
        if isinstance(value, int):
            varied = int(round(varied))
        render_data[field] = max(type(value)(minimum), type(value)(varied))
    except OverflowError:
        logger.debug(
            "Skipping Zeek sensor jitter for out-of-range numeric field %s on %s",
            field,
            hostname,
        )


def _jitter_duration_observation(
    render_data: dict[str, Any],
    hostname: str,
    uid: Any,
    magnitude: float,
    *,
    max_delta_seconds: float,
) -> None:
    """Apply bounded duration jitter for explicitly lossy sensor observations."""
    value = render_data.get("duration")
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return
    if value <= 0:
        return
    fraction = _sensor_variation_fraction(hostname, uid, "duration", magnitude)
    try:
        raw_delta = value * fraction
        delta = max(-max_delta_seconds, min(max_delta_seconds, raw_delta))
        if abs(delta) < 0.000001:
            delta = 0.000001 if raw_delta >= 0 else -0.000001
        render_data["duration"] = max(0.000001, value + delta)
    except OverflowError:
        logger.debug(
            "Skipping Zeek sensor duration jitter for out-of-range value on %s",
            hostname,
        )


def _extend_lossless_duration_observation(
    render_data: dict[str, Any],
    hostname: str,
    uid: Any,
    *,
    max_delta_seconds: float,
) -> None:
    """Apply small positive end-time texture for a lossless sensor observation."""
    value = render_data.get("duration")
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return
    if value <= 0:
        return
    seed = _stable_seed(f"zeek_sensor_lossless_duration:{hostname}:{uid}")
    fraction = 0.00075 + ((seed % 1200) / 1_000_000)
    try:
        raw_delta = max(0.000001, value * fraction)
        if raw_delta > max_delta_seconds:
            cap_seed = _stable_seed(f"zeek_sensor_lossless_duration_cap:{hostname}:{uid}")
            cap_fraction = 0.25 + ((cap_seed % 73_000) / 100_000)
            delta = max_delta_seconds * cap_fraction
        else:
            delta = raw_delta
        render_data["duration"] = value + delta
    except OverflowError:
        logger.debug(
            "Skipping Zeek lossless sensor duration texture for out-of-range value on %s",
            hostname,
        )


def _texture_lossless_tcp_packetization(
    render_data: dict[str, Any],
    hostname: str,
    uid: Any,
) -> None:
    """Add tiny packetization/IP-byte differences for an independent TCP tap."""
    if str(render_data.get("proto") or "").lower() != "tcp":
        return
    changed = False
    for side in ("orig", "resp"):
        packets = render_data.get(f"{side}_pkts")
        payload = render_data.get(f"{side}_bytes")
        ip_bytes = render_data.get(f"{side}_ip_bytes")
        if not all(isinstance(value, int) for value in (packets, payload, ip_bytes)):
            continue
        if packets <= 0 or payload < 0 or ip_bytes < 0:
            continue
        if packets > 10**18 or payload > 10**18 or ip_bytes > 10**18:
            continue
        seed = _stable_seed(f"zeek_sensor_lossless_packets:{hostname}:{uid}:{side}")
        if seed % 3 == 0:
            continue
        extra_packets = 1 + (seed % 2)
        render_data[f"{side}_pkts"] = packets + extra_packets
        render_data[f"{side}_ip_bytes"] = ip_bytes + (extra_packets * 40) + (seed % 97)
        changed = True
    if changed:
        return
    for side in ("orig", "resp"):
        packets = render_data.get(f"{side}_pkts")
        payload = render_data.get(f"{side}_bytes")
        ip_bytes = render_data.get(f"{side}_ip_bytes")
        if not all(isinstance(value, int) for value in (packets, payload, ip_bytes)):
            continue
        if packets <= 0 or payload < 0 or ip_bytes < 0:
            continue
        if packets > 10**18 or payload > 10**18 or ip_bytes > 10**18:
            continue
        seed = _stable_seed(f"zeek_sensor_lossless_packets:fallback:{hostname}:{uid}:{side}")
        render_data[f"{side}_pkts"] = packets + 1
        render_data[f"{side}_ip_bytes"] = ip_bytes + 40 + (seed % 53)
        return


def _jitter_payload_counter_with_floor(
    render_data: dict[str, Any],
    field: str,
    floor_field: str,
    hostname: str,
    uid: Any,
    magnitude: float,
) -> None:
    """Apply per-sensor byte jitter while preserving source-owned body floors."""
    value = render_data.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        return
    floor = render_data.get(floor_field)
    minimum = floor if isinstance(floor, int) and floor >= 0 else 0
    before = value
    _jitter_numeric_observation(
        render_data,
        field,
        hostname,
        uid,
        magnitude,
        minimum=minimum,
    )
    after = render_data.get(field)
    if after != before:
        return
    if before > 10**18 or minimum > 10**18:
        return

    seed = _stable_seed(f"zeek_sensor_payload_floor:{hostname}:{uid}:{field}")
    upper_extra = max(8, min(512, int(round(max(before, minimum, 1) * magnitude))))
    render_data[field] = max(minimum, before + 1 + (seed % upper_extra))


def _locks_sensor_packet_accounting(render_data: dict[str, Any]) -> bool:
    """Return whether a flow's byte counters should stay identical across sensors."""
    proto = str(render_data.get("proto") or "").lower()
    if proto == "icmp":
        return True
    if proto != "udp":
        return False
    service = str(render_data.get("service") or "").lower()
    if service == "dns":
        return True
    return render_data.get("id.orig_p") == 53 or render_data.get("id.resp_p") == 53


def _uses_bounded_bulk_tcp_accounting(render_data: dict[str, Any]) -> bool:
    """Return whether TCP sensor texture should be capped to small packet deltas."""
    if str(render_data.get("proto") or "").lower() != "tcp":
        return False
    missed = render_data.get("missed_bytes") or 0
    if not isinstance(missed, int) or isinstance(missed, bool) or missed < 0:
        return False
    if missed > _BULK_TCP_FLOW_MISSED_CAP_BYTES:
        return False

    total = 0
    for field in ("orig_ip_bytes", "resp_ip_bytes", "orig_bytes", "resp_bytes"):
        value = render_data.get(field)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            total += value
    return total >= _BULK_TCP_FLOW_MIN_IP_BYTES


def _extend_locked_sensor_timing_field(
    render_data: dict[str, Any],
    field: str,
    hostname: str,
    uid: Any,
    *,
    max_delta_seconds: float,
) -> bool:
    """Add tiny sensor-local timing texture while preserving packet accounting."""
    value = render_data.get(field)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    if value <= 0 or value > 10**18:
        return False
    seed = _stable_seed(f"zeek_sensor_locked_timing:{hostname}:{uid}:{field}")
    fraction = 0.0005 + ((seed % 6500) / 1_000_000)
    try:
        raw_delta = value * fraction
        if raw_delta < 0.000001:
            raw_delta = 0.000001
        if raw_delta > max_delta_seconds:
            cap_fraction = 0.2 + (((seed >> 8) % 7000) / 10_000)
            raw_delta = max_delta_seconds * cap_fraction
        render_data[field] = value + raw_delta
    except OverflowError:
        logger.debug(
            "Skipping Zeek locked packet-accounting timing texture for %s on %s",
            field,
            hostname,
        )
        return False
    return True


def _texture_locked_packet_accounting_observation(
    render_data: dict[str, Any],
    hostname: str,
    uid: Any,
) -> None:
    """Vary sensor-local timing for DNS/ICMP while keeping packet sizes exact."""
    _extend_locked_sensor_timing_field(
        render_data,
        "duration",
        hostname,
        uid,
        max_delta_seconds=0.05,
    )
    _extend_locked_sensor_timing_field(
        render_data,
        "rtt",
        hostname,
        uid,
        max_delta_seconds=0.025,
    )


def _texture_bounded_bulk_tcp_observation(
    render_data: dict[str, Any],
    hostname: str,
    uid: Any,
) -> None:
    """Keep bulk TCP bytes coherent while adding source-native tap texture."""
    if not render_data.get("_lock_duration"):
        _jitter_duration_observation(
            render_data,
            hostname,
            uid,
            0.002,
            max_delta_seconds=2.0,
        )
    _texture_lossless_tcp_packetization(render_data, hostname, uid)
    _enforce_http_body_invariants(render_data)
    _enforce_ip_byte_invariants(render_data)


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
    missed = render_data.get("missed_bytes") or 0
    lossy_observation = isinstance(missed, int) and missed > 0
    added_missed_bytes = False
    if "missed_bytes" in render_data:
        if isinstance(missed, int):
            seed = _stable_seed(f"zeek_sensor_missed:{hostname}:{original_uid}")
            if seed % 11 == 0:
                render_data["missed_bytes"] = missed + 16 + (seed % 496)
                added_missed_bytes = True
                lossy_observation = True
    if lossy_observation and _uses_bounded_bulk_tcp_accounting(render_data):
        _texture_bounded_bulk_tcp_observation(render_data, hostname, original_uid)
        return
    if not lossy_observation:
        if not render_data.get("_lock_duration"):
            _extend_lossless_duration_observation(
                render_data,
                hostname,
                original_uid,
                max_delta_seconds=0.75,
            )
        _texture_lossless_tcp_packetization(render_data, hostname, original_uid)
        _enforce_http_body_invariants(render_data)
        _enforce_ip_byte_invariants(render_data)
        return
    for field in ("orig_pkts", "resp_pkts"):
        _jitter_numeric_observation(
            render_data,
            field,
            hostname,
            original_uid,
            0.018 if added_missed_bytes else 0.012,
            minimum=1,
        )
    if not render_data.get("_lock_duration"):
        _jitter_duration_observation(
            render_data,
            hostname,
            original_uid,
            0.002,
            max_delta_seconds=2.0,
        )
    for field in ("orig_pkts", "resp_pkts"):
        _jitter_numeric_observation(render_data, field, hostname, original_uid, 0.035, minimum=1)
    _jitter_payload_counter_with_floor(
        render_data,
        "orig_bytes",
        "_http_request_body_len",
        hostname,
        original_uid,
        0.012,
    )
    _jitter_payload_counter_with_floor(
        render_data,
        "resp_bytes",
        "_http_response_body_len",
        hostname,
        original_uid,
        0.012,
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
    _enforce_http_body_invariants(render_data)
    _enforce_ip_byte_invariants(render_data)
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
            try:
                delta = max(duration * 0.0075, 0.000001)
                render_data["duration"] = max(0.000001, duration + (direction * delta))
            except OverflowError:
                logger.debug(
                    "Skipping Zeek sensor duration floor for out-of-range value on %s",
                    hostname,
                )
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
            if not self._direct_file_path:
                return
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
                    if "local_orig" in swaps and "local_orig" in render_data:
                        render_data["local_orig"] = swaps["local_orig"]
                    if "local_resp" in swaps and "local_resp" in render_data:
                        render_data["local_resp"] = swaps["local_resp"]
                    if "src_ip" in swaps and (
                        "tx_hosts" in render_data or "rx_hosts" in render_data
                    ):
                        original_src_ip = event_data.get("id.orig_h") or event_data.get(
                            "_id.orig_h"
                        )
                        if "tx_hosts" in render_data:
                            render_data["tx_hosts"] = _swap_host_list_value(
                                render_data.get("tx_hosts"),
                                original_src_ip,
                                swaps["src_ip"],
                            )
                        if "rx_hosts" in render_data:
                            render_data["rx_hosts"] = _swap_host_list_value(
                                render_data.get("rx_hosts"),
                                original_src_ip,
                                swaps["src_ip"],
                            )
                    if "dst_ip" in swaps and (
                        "tx_hosts" in render_data or "rx_hosts" in render_data
                    ):
                        original_dst_ip = event_data.get("id.resp_h") or event_data.get(
                            "_id.resp_h"
                        )
                        if "tx_hosts" in render_data:
                            render_data["tx_hosts"] = _swap_host_list_value(
                                render_data.get("tx_hosts"),
                                original_dst_ip,
                                swaps["dst_ip"],
                            )
                        if "rx_hosts" in render_data:
                            render_data["rx_hosts"] = _swap_host_list_value(
                                render_data.get("rx_hosts"),
                                original_dst_ip,
                                swaps["dst_ip"],
                            )
                # Each sensor has independent clock skew/drift plus stable
                # capture timing. Apply it to every sensor in a multi-sensor
                # observation so cross-sensor deltas are sensor/path-shaped
                # rather than per-record random.
                ts = render_data.get("ts")
                if len(targets) > 1 and ts is not None:
                    sensor_delay_us = _sensor_clock_adjustment_us(
                        hostname,
                        ts,
                    ) + _sensor_path_delay_us(hostname, original_uid)
                    if isinstance(ts, datetime):
                        render_data["ts"] = ts + timedelta(microseconds=sensor_delay_us)
                    elif isinstance(ts, (int, float)):
                        render_data["ts"] = ts + sensor_delay_us / 1_000_000
                if i > 0 and render_data.get("_allow_sensor_observation_variance"):
                    if _locks_sensor_packet_accounting(render_data):
                        _texture_locked_packet_accounting_observation(
                            render_data,
                            hostname,
                            original_uid,
                        )
                    else:
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
                for fuid_list_field in ("cert_chain_fuids", "resp_fuids", "fuids"):
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
