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

"""Cisco ASA firewall syslog emitter.

Renders ASA-format syslog entries for connection events observed by firewall
sensors. Produces Built/Teardown pairs for permitted connections and Deny
records for blocked connections.

Per-sensor/year directory routing: each firewall sensor gets cisco_asa.log files
partitioned by event year.
"""

import hashlib
import ipaddress
import math
import re
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from threading import Lock
from typing import Any, cast
from weakref import ReferenceType, ref

from evidenceforge.events.base import CanonicalOccurrence
from evidenceforge.events.network import (
    NatSensorObservation,
    NetworkSensorObservation,
    NetworkTransactionPlan,
)
from evidenceforge.formats.format_def import (
    EventVariant,
    FieldConstraint,
    FieldDefinition,
    FieldType,
    FormatDefinition,
    OutputTemplate,
)
from evidenceforge.generation.emitters.base import ExactPublicationError
from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
from evidenceforge.generation.emitters.syslog_family import (
    bounded_syslog_int,
    make_syslog_family_route_key,
    render_rfc3164_syslog,
    rfc3164_timestamp_sort_key,
    sanitize_syslog_family_route_key,
    syslog_family_writer_path,
)
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter, _SingleZeekWriter
from evidenceforge.output_targets import OutputTarget

# ASA facility: local4 (20)
_ASA_FACILITY = 20
_EXACT_FORMAT_MODEL_TAGS: tuple[tuple[type[object], str], ...] = (
    (FieldConstraint, "field_constraint"),
    (FieldDefinition, "field_definition"),
    (EventVariant, "event_variant"),
    (OutputTemplate, "output_template"),
    (FormatDefinition, "format_definition"),
)
_EXACT_FORMAT_SNAPSHOT_MAX_DEPTH = 64
_EXACT_FORMAT_SNAPSHOT_MAX_NODES = 100_000


def _exact_cisco_format_snapshot_value(value: object) -> object:
    """Freeze one ASA format-model value without invoking participant callbacks."""

    active_ids: set[int] = set()
    remaining_nodes = _EXACT_FORMAT_SNAPSHOT_MAX_NODES

    def freeze(item: object, depth: int) -> object:
        nonlocal remaining_nodes
        if depth > _EXACT_FORMAT_SNAPSHOT_MAX_DEPTH or remaining_nodes <= 0:
            raise ExactPublicationError("Exact Cisco ASA format snapshot exceeds its bound")
        remaining_nodes -= 1
        item_type = type(item)
        if item is None:
            return ("none",)
        if item_type is bool:
            return ("bool", item)
        if item_type is int:
            return ("int", item)
        if item_type is float:
            if not math.isfinite(cast(float, item)):
                raise ExactPublicationError("Exact Cisco ASA format contains a non-finite number")
            return ("float", item)
        if item_type is str:
            return ("str", item)
        if item_type is FieldType:
            enum_value = object.__getattribute__(item, "_value_")
            if type(enum_value) is not str:
                raise ExactPublicationError(
                    "Exact Cisco ASA format contains a malformed field type"
                )
            return ("field_type", enum_value)

        item_id = id(item)
        if item_id in active_ids:
            raise ExactPublicationError("Exact Cisco ASA format contains a reference cycle")
        active_ids.add(item_id)
        try:
            if item_type is list:
                return ("list", tuple(freeze(child, depth + 1) for child in item))
            if item_type is tuple:
                return ("tuple", tuple(freeze(child, depth + 1) for child in item))
            if item_type is dict:
                entries: list[tuple[object, object]] = []
                for key, child in dict.items(cast(dict[object, object], item)):
                    if type(key) is not str and type(key) is not int:
                        raise ExactPublicationError(
                            "Exact Cisco ASA format contains a non-scalar mapping key"
                        )
                    entries.append((freeze(key, depth + 1), freeze(child, depth + 1)))
                return ("dict", tuple(entries))
            model_tag = None
            for model_type, tag in _EXACT_FORMAT_MODEL_TAGS:
                if item_type is model_type:
                    model_tag = tag
                    break
            if model_tag is not None:
                state = object.__getattribute__(item, "__dict__")
                if type(state) is not dict:
                    raise ExactPublicationError(
                        "Exact Cisco ASA format model state must be an exact dict"
                    )
                fields: list[tuple[str, object]] = []
                for key, child in dict.items(state):
                    if type(key) is not str:
                        raise ExactPublicationError(
                            "Exact Cisco ASA format model key must be an exact str"
                        )
                    fields.append((key, freeze(child, depth + 1)))
                return ("model", model_tag, tuple(fields))
            raise ExactPublicationError("Exact Cisco ASA format contains an unsupported value type")
        finally:
            active_ids.remove(item_id)

    return freeze(value, 0)


def _exact_cisco_format_snapshot(format_definition: object) -> tuple[object, ...]:
    """Return one callback-free inert snapshot of the built-in ASA format."""

    if type(format_definition) is not FormatDefinition:
        raise ExactPublicationError("Exact Cisco ASA format must be one exact FormatDefinition")
    snapshot = _exact_cisco_format_snapshot_value(format_definition)
    if type(snapshot) is not tuple:
        raise ExactPublicationError("Exact Cisco ASA format snapshot is malformed")
    return cast(tuple[object, ...], snapshot)


@dataclass(frozen=True, slots=True)
class _CiscoExactWriterSettings:
    """Immutable writer construction truth retained outside the emitter instance."""

    buffer_size: int
    sort_before_flush: bool
    external_sorting: bool
    sort_key: Callable[[str], Any]


@dataclass(frozen=True, slots=True)
class _CiscoExactProjectionBinding:
    """Closure-retained constructor truth for deferred exact ASA publication."""

    builtin_format: bool
    format_definition_id: int
    format_snapshot: tuple[object, ...] | None
    writers_id: int
    writers_lock_id: int
    writer_settings: _CiscoExactWriterSettings


def _new_cisco_exact_projection_binding_registry() -> tuple[
    Callable[[object, object, int], None],
    Callable[[object], bool],
    Callable[[object], _CiscoExactWriterSettings | None],
]:
    """Create the callback-free constructor and writer capability registry."""

    from evidenceforge.config import get_formats_directory
    from evidenceforge.formats.loader import load_format
    from evidenceforge.utils.files import load_yaml

    canonical_data = load_yaml(get_formats_directory() / "cisco_asa.yaml")
    if type(canonical_data) is not dict:
        raise ExactPublicationError("Built-in Cisco ASA format must decode to one exact mapping")
    canonical_snapshot = _exact_cisco_format_snapshot(FormatDefinition(**canonical_data))
    bindings: dict[int, tuple[ReferenceType[object], _CiscoExactProjectionBinding]] = {}
    registry_lock = Lock()

    def discard(owner_id: int, owner_reference: ReferenceType[object]) -> None:
        with registry_lock:
            retained = bindings.get(owner_id)
            if retained is not None and retained[0] is owner_reference:
                bindings.pop(owner_id, None)

    def bind(owner: object, format_definition: object, buffer_size: int) -> None:
        current_snapshot: tuple[object, ...] | None = None
        if type(format_definition) is FormatDefinition:
            try:
                current_snapshot = _exact_cisco_format_snapshot(format_definition)
            except ExactPublicationError:
                current_snapshot = None
        owner_state = object.__getattribute__(owner, "__dict__")
        if type(owner_state) is not dict:
            raise ExactPublicationError("Exact Cisco ASA emitter state must be an exact dict")
        writers = dict.get(owner_state, "_writers")
        writers_lock = dict.get(owner_state, "_writers_lock")
        if type(writers) is not dict or writers_lock is None:
            raise ExactPublicationError("Exact Cisco ASA writer topology is malformed")
        if type(buffer_size) is not int or buffer_size <= 0:
            raise ExactPublicationError(
                "Exact Cisco ASA writer buffer size must be a positive exact int"
            )
        owner_id = id(owner)
        owner_reference = ref(
            owner,
            lambda expired, retained_id=owner_id: discard(retained_id, expired),
        )
        binding = _CiscoExactProjectionBinding(
            builtin_format=(
                format_definition is load_format("cisco_asa")
                and current_snapshot == canonical_snapshot
            ),
            format_definition_id=id(format_definition),
            format_snapshot=current_snapshot,
            writers_id=id(writers),
            writers_lock_id=id(writers_lock),
            writer_settings=_CiscoExactWriterSettings(
                buffer_size=buffer_size,
                sort_before_flush=True,
                external_sorting=True,
                sort_key=rfc3164_timestamp_sort_key,
            ),
        )
        with registry_lock:
            retained = bindings.get(owner_id)
            if retained is not None and retained[0]() is not owner:
                raise ExactPublicationError("Exact Cisco ASA emitter identity was recycled")
            bindings[owner_id] = (owner_reference, binding)

    def binding_for(owner: object) -> _CiscoExactProjectionBinding | None:
        with registry_lock:
            retained = bindings.get(id(owner))
            if retained is None or retained[0]() is not owner:
                return None
            return retained[1]

    def writer_settings(owner: object) -> _CiscoExactWriterSettings | None:
        binding = binding_for(owner)
        if binding is None:
            return None
        owner_state = object.__getattribute__(owner, "__dict__")
        if type(owner_state) is not dict:
            return None
        writers = dict.get(owner_state, "_writers")
        writers_lock = dict.get(owner_state, "_writers_lock")
        if id(writers) != binding.writers_id or id(writers_lock) != binding.writers_lock_id:
            return None
        return binding.writer_settings

    def writer_authenticates(
        writer: object,
        settings: _CiscoExactWriterSettings,
    ) -> bool:
        if type(writer) is not _SingleZeekWriter:
            return False
        writer_state = object.__getattribute__(writer, "__dict__")
        if type(writer_state) is not dict:
            return False
        sorted_writer = dict.get(writer_state, "_sorted_writer")
        if type(sorted_writer) is not ExternalSortedLineWriter:
            return False
        sorted_state = object.__getattribute__(sorted_writer, "__dict__")
        if type(sorted_state) is not dict:
            return False
        return bool(
            dict.get(writer_state, "buffer_size") == settings.buffer_size
            and dict.get(writer_state, "_sort_before_flush") is settings.sort_before_flush
            and dict.get(writer_state, "_sort_key") is settings.sort_key
            and dict.get(writer_state, "_closed") is False
            and dict.get(writer_state, "_close_state") == "open"
            and dict.get(sorted_state, "buffer_size") == settings.buffer_size
            and dict.get(sorted_state, "_sort_key") is settings.sort_key
            and dict.get(sorted_state, "_closed") is False
            and dict.get(sorted_state, "_close_state") == "open"
            and dict.get(writer_state, "output_path") is dict.get(sorted_state, "output_path")
        )

    def authenticates(owner: object) -> bool:
        if type(owner) is not CiscoAsaEmitter:
            return False
        owner_state = object.__getattribute__(owner, "__dict__")
        if type(owner_state) is not dict:
            return False
        format_definition = dict.get(owner_state, "format_def")
        writers = dict.get(owner_state, "_writers")
        writers_lock = dict.get(owner_state, "_writers_lock")
        if type(format_definition) is not FormatDefinition or type(writers) is not dict:
            return False
        try:
            current_snapshot = _exact_cisco_format_snapshot(format_definition)
        except ExactPublicationError:
            return False
        binding = binding_for(owner)
        return bool(
            binding is not None
            and binding.builtin_format
            and binding.format_definition_id == id(format_definition)
            and binding.format_snapshot == current_snapshot
            and current_snapshot == canonical_snapshot
            and binding.writers_id == id(writers)
            and binding.writers_lock_id == id(writers_lock)
            and all(
                type(route_key) is str and writer_authenticates(writer, binding.writer_settings)
                for route_key, writer in dict.items(writers)
            )
        )

    return bind, authenticates, writer_settings


(
    _bind_cisco_exact_projection_publication,
    _authenticates_cisco_exact_projection_publication,
    _cisco_exact_writer_settings,
) = _new_cisco_exact_projection_binding_registry()


def _supports_cisco_asa_exact_projection_publication(emitter: object) -> bool:
    """Authenticate concrete type, constructor format, and live final writers."""

    return _authenticates_cisco_exact_projection_publication(emitter)


@dataclass(frozen=True, slots=True)
class _AsaNetworkProjection:
    """Source-local network values needed to render one ASA observation."""

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    duration: float | None
    conn_state: str
    orig_bytes: int
    resp_bytes: int
    orig_ip_bytes: int
    resp_ip_bytes: int

    @classmethod
    def from_observation(
        cls,
        canonical: NetworkTransactionPlan,
        observation: NetworkSensorObservation,
    ) -> "_AsaNetworkProjection":
        """Project an observation without reconstructing canonical transaction truth."""

        return cls(
            src_ip=observation.tuple_view.src_ip,
            src_port=observation.tuple_view.src_port,
            dst_ip=observation.tuple_view.dst_ip,
            dst_port=observation.tuple_view.dst_port,
            protocol=observation.tuple_view.protocol,
            duration=(
                None
                if observation.observed_close_time is None
                else (
                    observation.observed_close_time - observation.observed_start_time
                ).total_seconds()
            ),
            conn_state=canonical.conn_state,
            orig_bytes=observation.traffic.orig.payload_bytes,
            resp_bytes=observation.traffic.resp.payload_bytes,
            orig_ip_bytes=observation.traffic.orig.ip_bytes,
            resp_ip_bytes=observation.traffic.resp.ip_bytes,
        )


@dataclass(frozen=True, slots=True)
class _AsaRouteProjection:
    """One allocation-free ASA route decision shared with compiled admission."""

    timestamp: datetime
    network: Any
    src_interface: str
    dst_interface: str
    nat: NatSensorObservation | None

    @property
    def emits_rows(self) -> bool:
        """Return whether this interface/NAT view can produce ASA evidence."""

        return self.src_interface != self.dst_interface or self.nat is not None


class CiscoAsaEmitter(SensorMultiplexEmitter):
    """Emitter for Cisco ASA firewall syslog format.

    Default target writes flat per-sensor files. SOF-ELK target writes
    per-sensor/year files so BSD-syslog archive consumers can infer years.

    Handles all connection events visible to firewall sensors. Unlike Snort
    (which requires IdsAlertPlan), the ASA emitter renders every connection it
    sees -- either as a permit (Built/Teardown) or deny (Deny) record.
    """

    _log_filename = "cisco_asa.log"
    _flat_filename = "cisco_asa.log"
    _supported_types: set[str] = {"connection"}
    _sort_before_flush = True
    _external_sorting = True
    _sort_key_func = staticmethod(rfc3164_timestamp_sort_key)
    supports_exact_projection_publication = True

    def __init__(
        self,
        format_def: FormatDefinition,
        output_path: Path,
        buffer_size: int = 10000,
        threaded: bool = False,
        sensor_hostnames: list[str] | None = None,
    ):
        super().__init__(format_def, output_path, buffer_size, threaded, sensor_hostnames)
        # Network segment config for interface resolution (set by emitter_setup)
        self._segment_config: list[dict[str, str]] = []
        # Per-sensor interface mappings (set by emitter_setup)
        self._sensor_interfaces: dict[str, dict[str, str]] = {}
        # Optional ASA nameif security levels (set by emitter_setup).
        self._sensor_security_levels: dict[str, dict[str, int]] = {}
        # VIP→real_ip for interface resolution (set by emitter_setup)
        self._vip_to_real_ip: dict[str, str] = {}
        # Threat detection: per-(sensor, src_ip) deny rate tracking
        self._deny_timestamps: dict[tuple[str, str], deque[datetime]] = {}
        self._last_alert_time: dict[tuple[str, str], datetime | None] = {}
        # Configurable thresholds (ASA defaults for scanning detection)
        self._td_burst_threshold: int = 10  # drops/sec to trigger burst alert
        self._td_avg_threshold: int = 5  # drops/sec to trigger average alert
        self._td_burst_window: int = 20  # seconds for burst rate calculation
        self._td_avg_window: int = 60  # seconds for average rate calculation
        self._td_cooldown: int = 20  # seconds between re-firings (= burst period)
        _bind_cisco_exact_projection_publication(self, format_def, buffer_size)

    def _safe_writer_key(self, sensor_hostname: str) -> str:
        return sanitize_syslog_family_route_key(sensor_hostname)

    def _writer_path_for_key(self, safe_writer_key: str) -> Path:
        return syslog_family_writer_path(
            base_dir=self._base_dir,
            safe_route_key=safe_writer_key,
            log_filename=self._log_filename,
            direct_file_path=self._direct_file_path,
            flat_filename=self._flat_filename,
        )

    def _get_writer(self, sensor_hostname: str) -> _SingleZeekWriter:
        """Create ASA writers only from constructor-bound exact sort settings."""

        settings = _cisco_exact_writer_settings(self)
        owner_state = object.__getattribute__(self, "__dict__")
        if settings is None or type(owner_state) is not dict:
            raise ExactPublicationError("Cisco ASA writer constructor binding is unavailable")
        writers = dict.get(owner_state, "_writers")
        writers_lock = dict.get(owner_state, "_writers_lock")
        if type(writers) is not dict or writers_lock is None:
            raise ExactPublicationError("Cisco ASA writer topology is malformed")
        safe_sensor = CiscoAsaEmitter._safe_writer_key(self, sensor_hostname)
        writer = dict.get(writers, safe_sensor)
        if writer is not None:
            if type(writer) is not _SingleZeekWriter:
                raise ExactPublicationError("Cisco ASA retained a foreign sensor writer")
            return writer
        with cast(Any, writers_lock):
            writer = dict.get(writers, safe_sensor)
            if writer is not None:
                if type(writer) is not _SingleZeekWriter:
                    raise ExactPublicationError("Cisco ASA retained a foreign sensor writer")
                return writer
            path = CiscoAsaEmitter._writer_path_for_key(self, safe_sensor)
            writer = _SingleZeekWriter(
                path,
                settings.buffer_size,
                sort_before_flush=settings.sort_before_flush,
                sort_key=settings.sort_key,
                external_sorting=settings.external_sorting,
                checkpoint_mode=self._incremental_checkpointing,
                defer_publication=self._defer_sorted_publication,
            )
            dict.__setitem__(writers, safe_sensor, writer)
            return writer

    @staticmethod
    def _connection_id(event: CanonicalOccurrence, sensor_hostname: str) -> int:
        """Return the retry-invariant final ASA ID for one canonical transport."""

        network = event.network
        if network is None:
            raise ValueError("ASA connection IDs require canonical network truth")
        sensor_key = sensor_hostname.casefold()
        sensor_digest = hashlib.sha256(f"asa-sensor:{sensor_key}".encode()).digest()
        sensor_base = 1_000_000 + int.from_bytes(sensor_digest[:4], "big") % 1_000_000
        canonical_match = re.fullmatch(r"conn-(0|[1-9][0-9]*)", network.conn_id)
        if canonical_match is not None:
            return sensor_base + int(canonical_match.group(1))
        compatibility_digest = hashlib.sha256(
            f"asa-compatibility-connection:{sensor_key}:{network.stable_id}".encode()
        ).digest()
        return 1_000_000 + int.from_bytes(compatibility_digest[:8], "big") % 999_000_000

    @staticmethod
    def _compatibility_teardown_plan(net: Any, protocol: str) -> tuple[str, float]:
        """Project legacy direct-emitter calls without per-flow random synthesis."""

        if protocol != "tcp":
            return "", float(getattr(net, "duration", None) or 0)
        state = getattr(net, "conn_state", "") or ""
        payload_bytes = (getattr(net, "orig_bytes", 0) or 0) + (getattr(net, "resp_bytes", 0) or 0)
        if state in {"S0", "S1", "SH", "SHR"} and payload_bytes == 0:
            return "SYN Timeout", 30.0
        if state in {"REJ", "RSTO"}:
            return "TCP Reset-O", float(getattr(net, "duration", None) or 0)
        if state == "RSTR":
            return "TCP Reset-I", float(getattr(net, "duration", None) or 0)
        if state == "OTH":
            return "TCP Reset-O", float(getattr(net, "duration", None) or 0)
        return "TCP FINs", float(getattr(net, "duration", None) or 0)

    def _resolve_interface(self, ip: str, sensor_hostname: str) -> str:
        """Resolve an IP address to an ASA interface name.

        Looks up which segment the IP belongs to, then maps the segment name
        to an interface name via the sensor's interfaces dict. Falls back to
        segment name, then "outside" for unknown IPs.

        VIPs (public NAT addresses) are resolved via their real_ip's segment.
        """
        # Resolve VIP → real_ip for segment lookup
        lookup_ip = self._vip_to_real_ip.get(ip, ip) if self._vip_to_real_ip else ip
        interfaces = self._sensor_interfaces.get(sensor_hostname, {})
        for seg in self._segment_config:
            try:
                if ipaddress.ip_address(lookup_ip) in ipaddress.ip_network(
                    seg["cidr"], strict=False
                ):
                    seg_name = seg["name"]
                    return interfaces.get(seg_name, seg_name)
            except (ValueError, KeyError):
                continue
        return interfaces.get("_default", "outside")

    @staticmethod
    def _pri(severity: int) -> int:
        """Calculate syslog priority from ASA severity."""
        return _ASA_FACILITY * 8 + severity

    @staticmethod
    def _format_duration(seconds: float | None) -> str:
        """Format duration as H:MM:SS."""
        if seconds is None or seconds <= 0:
            return "0:00:00"
        td = timedelta(seconds=int(seconds))
        total_seconds = int(td.total_seconds())
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        secs = total_seconds % 60
        return f"{hours}:{minutes:02d}:{secs:02d}"

    @staticmethod
    def _teardown_byte_count(net: Any, protocol: str, conn_id: int) -> int:
        """Project finalized sensor accounting into ASA's total-byte field."""
        orig_payload = getattr(net, "orig_bytes", 0) or 0
        resp_payload = getattr(net, "resp_bytes", 0) or 0
        payload_total = orig_payload + resp_payload
        if payload_total <= 0:
            return 0

        orig_ip_bytes = getattr(net, "orig_ip_bytes", None)
        resp_ip_bytes = getattr(net, "resp_ip_bytes", None)
        if orig_ip_bytes is not None or resp_ip_bytes is not None:
            return int((orig_ip_bytes or orig_payload) + (resp_ip_bytes or resp_payload))
        return int(payload_total)

    def can_handle(self, event: CanonicalOccurrence) -> bool:
        """Handle all connection events with network context."""
        return (
            event.event_type in self._supported_types
            and event.network is not None
            and not event.network.application_layer_only
        )

    def _route_projection(
        self,
        event: CanonicalOccurrence,
        sensor_hostname: str,
        observation: NetworkSensorObservation | None,
    ) -> _AsaRouteProjection:
        """Resolve one source-local ASA view without allocating or writing anything."""

        network = event.network
        if network is None:
            raise ValueError("ASA route projection requires canonical network truth")
        timestamp = event.timestamp
        projected_network: Any = network
        if observation is not None:
            timestamp = observation.observed_start_time
            projected_network = _AsaNetworkProjection.from_observation(network, observation)
        src_interface = self._resolve_interface(projected_network.src_ip, sensor_hostname)
        dst_interface = self._resolve_interface(projected_network.dst_ip, sensor_hostname)
        firewall = event.firewall
        if firewall is not None:
            src_interface = firewall.src_interface or src_interface
            dst_interface = firewall.dst_interface or dst_interface
        return _AsaRouteProjection(
            timestamp=timestamp,
            network=projected_network,
            src_interface=src_interface,
            dst_interface=dst_interface,
            nat=self._nat_view(event, projected_network, observation),
        )

    def emit(self, event: CanonicalOccurrence) -> None:
        """Render ASA syslog records from a connection event.

        For permitted connections: emits a Built record + Teardown record.
        For denied connections: emits a single Deny record.
        """
        net = event.network
        if net is None:
            return

        fw = event.firewall
        is_deny = fw is not None and fw.action == "deny"
        protocol = (net.protocol or "tcp").lower()

        # Get sensor routing from visibility metadata
        observations = {
            observation.sensor_identity: observation
            for observation in event.network_observations
            if "cisco_asa" in observation.visible_formats
        }
        sensor_hosts: list[str] = list(observations)
        if not event.network_observations_planned:
            sensor_hosts = event._sensor_hostnames_by_format.get("cisco_asa", [])
        if not sensor_hosts:
            if event.network_observations_planned:
                return
            sensor_hosts = self._sensor_hostnames or [""]

        for sensor_hostname in sensor_hosts:
            observation = observations.get(sensor_hostname)
            route = self._route_projection(event, sensor_hostname, observation)
            if not route.emits_rows:
                continue
            sensor_timestamp = route.timestamp
            sensor_net = route.network
            src_iface = route.src_interface
            dst_iface = route.dst_interface
            nat_view = route.nat
            fw_hostname = sensor_hostname or "fw01"

            if is_deny:
                if self._should_suppress_outside_private_deny(
                    sensor_net, src_iface, dst_iface, sensor_hostname
                ):
                    continue
                self._emit_deny(
                    sensor_timestamp,
                    sensor_net,
                    fw,
                    src_iface,
                    dst_iface,
                    sensor_hostname,
                    fw_hostname,
                )
            else:
                conn_id = (
                    fw.connection_id
                    if fw is not None and fw.connection_id > 0
                    else self._connection_id(event, sensor_hostname)
                )
                if nat_view is not None and nat_view.nat_type != "static":
                    self._emit_nat_built(
                        sensor_net,
                        protocol,
                        src_iface,
                        dst_iface,
                        sensor_hostname,
                        fw_hostname,
                        nat_view,
                    )
                self._emit_built(
                    sensor_timestamp,
                    sensor_net,
                    protocol,
                    conn_id,
                    src_iface,
                    dst_iface,
                    sensor_hostname,
                    fw_hostname,
                    nat_view,
                )
                teardown_emitted = self._emit_teardown(
                    sensor_timestamp,
                    sensor_net,
                    protocol,
                    conn_id,
                    src_iface,
                    dst_iface,
                    sensor_hostname,
                    fw_hostname,
                    observation,
                    nat_view,
                )
                if nat_view is not None and nat_view.nat_type != "static":
                    if teardown_emitted:
                        self._emit_nat_teardown(
                            sensor_net,
                            protocol,
                            src_iface,
                            dst_iface,
                            sensor_hostname,
                            fw_hostname,
                            nat_view,
                        )

    @classmethod
    def _nat_view(
        cls,
        event: CanonicalOccurrence,
        net: Any,
        observation: NetworkSensorObservation | None,
    ) -> NatSensorObservation | None:
        """Return the planned NAT view, with direct-emission compatibility fallback."""

        if observation is not None:
            return observation.nat
        nat = event.nat
        if nat is None:
            return None
        teardown_time = None
        if nat.nat_type == "dynamic_pat" and net.duration is not None:
            _reason, teardown_seconds = cls._compatibility_teardown_plan(
                net,
                (net.protocol or "tcp").lower(),
            )
            teardown_time = event.timestamp + timedelta(seconds=max(0.0, teardown_seconds))
        if nat.mapped_src_ip != net.src_ip or nat.mapped_src_port != net.src_port:
            return NatSensorObservation(
                nat_type=nat.nat_type,
                direction="source",
                local_ip=net.src_ip,
                local_port=net.src_port,
                global_ip=nat.mapped_src_ip,
                global_port=nat.mapped_src_port,
                built_time=event.timestamp,
                teardown_time=teardown_time,
            )
        global_ip = nat.pre_nat_dst_ip or net.dst_ip
        global_port = nat.pre_nat_dst_port or net.dst_port
        if nat.mapped_dst_ip != global_ip or nat.mapped_dst_port != global_port:
            return NatSensorObservation(
                nat_type=nat.nat_type,
                direction="destination",
                local_ip=nat.mapped_dst_ip,
                local_port=nat.mapped_dst_port,
                global_ip=global_ip,
                global_port=global_port,
                built_time=event.timestamp,
                teardown_time=teardown_time,
            )
        return None

    def _emit_built(
        self,
        timestamp: datetime,
        net: Any,
        protocol: str,
        conn_id: int,
        src_iface: str,
        dst_iface: str,
        sensor_hostname: str,
        fw_hostname: str,
        nat: NatSensorObservation | None,
    ) -> None:
        """Emit a Built connection record (302013/302015/302020)."""
        direction = self._connection_direction(src_iface, dst_iface, sensor_hostname)

        if protocol == "icmp":
            msg_id = 302020
            icmp_type = net.dst_port if net.dst_port else 8  # Default echo request
            if direction == "inbound":
                foreign_ip = net.src_ip
                global_ip = nat.global_ip if nat is not None else net.dst_ip
                local_ip = nat.local_ip if nat is not None else net.dst_ip
            else:
                foreign_ip = net.dst_ip
                global_ip = nat.global_ip if nat is not None else net.src_ip
                local_ip = nat.local_ip if nat is not None else net.src_ip
            message = (
                f"Built {direction} ICMP connection for faddr "
                f"{foreign_ip}/{icmp_type} "
                f"gaddr {global_ip}/0 "
                f"laddr {local_ip}/0"
            )
        else:
            msg_id = 302013 if protocol == "tcp" else 302015
            proto_upper = protocol.upper()
            # ASA format: iface:real_ip/port (mapped_ip/port)
            # For inbound static NAT: dst main=real_ip, dst parens=VIP
            # For outbound PAT: src main=real_ip, src parens=mapped_ip
            if nat is not None and nat.direction == "destination":
                display_dst_ip, display_dst_port = nat.local_ip, nat.local_port
                paren_dst_ip, paren_dst_port = nat.global_ip, nat.global_port
            else:
                display_dst_ip, display_dst_port = net.dst_ip, net.dst_port
                paren_dst_ip, paren_dst_port = net.dst_ip, net.dst_port
            if nat is not None and nat.direction == "source":
                mapped_src_ip, mapped_src_port = nat.global_ip, nat.global_port
            else:
                mapped_src_ip, mapped_src_port = net.src_ip, net.src_port
            message = (
                f"Built {direction} {proto_upper} connection {conn_id} for "
                f"{src_iface}:{net.src_ip}/{net.src_port} "
                f"({mapped_src_ip}/{mapped_src_port}) to "
                f"{dst_iface}:{display_dst_ip}/{display_dst_port} "
                f"({paren_dst_ip}/{paren_dst_port})"
            )

        event_data = {
            "timestamp": timestamp,
            "hostname": fw_hostname,
            "severity": 6,
            "msg_id": msg_id,
            "message": message,
            "pri": self._pri(6),
            "_sensor_hostnames": [sensor_hostname] if sensor_hostname else None,
        }
        self._dispatch(event_data)

    def _emit_teardown(
        self,
        timestamp: datetime,
        net: Any,
        protocol: str,
        conn_id: int,
        src_iface: str,
        dst_iface: str,
        sensor_hostname: str,
        fw_hostname: str,
        observation: Any | None = None,
        nat: NatSensorObservation | None = None,
    ) -> bool:
        """Emit a Teardown connection record (302014/302016/302021)."""
        if observation is not None and not observation.firewall_teardown_observed:
            return False
        if observation is not None and observation.firewall_teardown_time is not None:
            reason = observation.firewall_teardown_reason
            teardown_ts = observation.firewall_teardown_time
            duration_seconds = max(0.0, (teardown_ts - timestamp).total_seconds())
        else:
            reason, duration_seconds = self._compatibility_teardown_plan(net, protocol)
            teardown_ts = timestamp + timedelta(seconds=duration_seconds)
        duration = self._format_duration(duration_seconds)
        total_bytes = self._teardown_byte_count(net, protocol, conn_id)

        if protocol == "icmp":
            msg_id = 302021
            icmp_type = net.dst_port if net.dst_port else 8
            direction = self._connection_direction(src_iface, dst_iface, sensor_hostname)
            if direction == "inbound":
                foreign_ip = net.src_ip
                global_ip = nat.global_ip if nat is not None else net.dst_ip
                local_ip = nat.local_ip if nat is not None else net.dst_ip
            else:
                foreign_ip = net.dst_ip
                global_ip = nat.global_ip if nat is not None else net.src_ip
                local_ip = nat.local_ip if nat is not None else net.src_ip
            message = (
                f"Teardown ICMP connection for faddr "
                f"{foreign_ip}/{icmp_type} "
                f"gaddr {global_ip}/0 "
                f"laddr {local_ip}/0"
            )
        else:
            msg_id = 302014 if protocol == "tcp" else 302016
            proto_upper = protocol.upper()
            # Inbound static NAT: teardown shows real (post-NAT) dst IP
            is_inbound_nat = nat is not None and nat.direction == "destination"
            td_dst_ip = nat.local_ip if is_inbound_nat else net.dst_ip
            td_dst_port = nat.local_port if is_inbound_nat else net.dst_port
            message = (
                f"Teardown {proto_upper} connection {conn_id} for "
                f"{src_iface}:{net.src_ip}/{net.src_port} to "
                f"{dst_iface}:{td_dst_ip}/{td_dst_port} "
                f"duration {duration} bytes {total_bytes}"
            )
            if reason:
                message += f" {reason}"

        event_data = {
            "timestamp": teardown_ts,
            "hostname": fw_hostname,
            "severity": 6,
            "msg_id": msg_id,
            "message": message,
            "pri": self._pri(6),
            "_sensor_hostnames": [sensor_hostname] if sensor_hostname else None,
        }
        self._dispatch(event_data)
        return True

    def _connection_direction(
        self,
        src_iface: str,
        dst_iface: str,
        sensor_hostname: str,
    ) -> str:
        """Return ASA direction from the initiating interface security relationship."""

        configured = self._sensor_security_levels.get(sensor_hostname, {})
        conventional = {"outside": 0, "dmz": 50, "inside": 100}
        src_level = configured.get(src_iface, conventional.get(src_iface.lower()))
        dst_level = configured.get(dst_iface, conventional.get(dst_iface.lower()))
        if src_level is not None and dst_level is not None and src_level != dst_level:
            return "inbound" if src_level < dst_level else "outbound"
        # Preserve compatibility for custom and same-security interfaces whose
        # relationship was not declared.
        return "inbound" if src_iface.lower() == "outside" else "outbound"

    def _emit_deny(
        self,
        timestamp: datetime,
        net: Any,
        fw: Any,
        src_iface: str,
        dst_iface: str,
        sensor_hostname: str,
        fw_hostname: str,
    ) -> None:
        """Emit a Deny record (106023)."""
        protocol = (net.protocol or "tcp").lower()
        acl_name = (fw.access_group if fw else "") or "outside_access_in"
        deny_hash_a = getattr(fw, "deny_hash_a", "0x0") if fw else "0x0"
        deny_hash_b = getattr(fw, "deny_hash_b", "0x0") if fw else "0x0"

        if protocol == "icmp":
            icmp_type = net.dst_port if net.dst_port else 8
            icmp_code = 0
            message = (
                f"Deny {protocol} src {src_iface}:{net.src_ip} "
                f"dst {dst_iface}:{net.dst_ip} "
                f"(type {icmp_type}, code {icmp_code}) "
                f'by access-group "{acl_name}" [{deny_hash_a}, {deny_hash_b}]'
            )
        else:
            message = (
                f"Deny {protocol} src {src_iface}:{net.src_ip}/{net.src_port} "
                f"dst {dst_iface}:{net.dst_ip}/{net.dst_port} "
                f'by access-group "{acl_name}" [{deny_hash_a}, {deny_hash_b}]'
            )

        event_data = {
            "timestamp": timestamp,
            "hostname": fw_hostname,
            "severity": 4,
            "msg_id": fw.msg_id if fw and fw.msg_id > 0 else 106023,
            "message": message,
            "pri": self._pri(4),
            "_sensor_hostnames": [sensor_hostname] if sensor_hostname else None,
        }
        self._dispatch(event_data)
        # Check threat detection thresholds after each deny
        self._check_threat_detection(net.src_ip, timestamp, sensor_hostname, fw_hostname)

    def _should_suppress_outside_private_deny(
        self,
        net: Any,
        src_iface: str,
        dst_iface: str,
        sensor_hostname: str,
    ) -> bool:
        """Suppress impossible outside denies to unmapped private post-NAT hosts."""
        if src_iface != "outside" or dst_iface != "dmz":
            return False
        try:
            dst_addr = ipaddress.ip_address(net.dst_ip)
        except ValueError:
            return False
        if not dst_addr.is_private:
            return False
        return net.dst_ip not in set(self._vip_to_real_ip.values())

    def _emit_nat_built(
        self,
        net: Any,
        protocol: str,
        src_iface: str,
        dst_iface: str,
        sensor_hostname: str,
        fw_hostname: str,
        nat: NatSensorObservation,
    ) -> None:
        """Emit a NAT translation Built record (305011)."""
        nat_label = "dynamic" if nat.nat_type == "dynamic_pat" else "static"
        proto_upper = protocol.upper()
        if nat.direction == "source":
            mapped_src_iface = self._sensor_interfaces.get(sensor_hostname, {}).get(
                "_default", "outside"
            )
            message = (
                f"Built {nat_label} {proto_upper} translation from "
                f"{src_iface}:{nat.local_ip}/{nat.local_port} to "
                f"{mapped_src_iface}:{nat.global_ip}/{nat.global_port}"
            )
        else:
            # Destination NAT (static inbound): public IP is on outside,
            # real IP is on dmz/inside
            public_iface = self._sensor_interfaces.get(sensor_hostname, {}).get(
                "_default", "outside"
            )
            real_iface = self._resolve_interface(nat.local_ip, sensor_hostname)
            message = (
                f"Built {nat_label} {proto_upper} translation from "
                f"{public_iface}:{nat.global_ip}/{nat.global_port} to "
                f"{real_iface}:{nat.local_ip}/{nat.local_port}"
            )
        event_data = {
            "timestamp": nat.built_time,
            "hostname": fw_hostname,
            "severity": 6,
            "msg_id": 305011,
            "message": message,
            "pri": self._pri(6),
            "_sensor_hostnames": [sensor_hostname] if sensor_hostname else None,
        }
        self._dispatch(event_data)

    def _emit_nat_teardown(
        self,
        net: Any,
        protocol: str,
        src_iface: str,
        dst_iface: str,
        sensor_hostname: str,
        fw_hostname: str,
        nat: NatSensorObservation,
    ) -> None:
        """Emit a NAT translation Teardown record (305012)."""
        nat_label = "dynamic" if nat.nat_type == "dynamic_pat" else "static"
        proto_upper = protocol.upper()
        teardown_ts = nat.teardown_time or nat.built_time
        duration = self._format_duration((teardown_ts - nat.built_time).total_seconds())
        if nat.direction == "source":
            mapped_src_iface = self._sensor_interfaces.get(sensor_hostname, {}).get(
                "_default", "outside"
            )
            message = (
                f"Teardown {nat_label} {proto_upper} translation from "
                f"{src_iface}:{nat.local_ip}/{nat.local_port} to "
                f"{mapped_src_iface}:{nat.global_ip}/{nat.global_port} "
                f"duration {duration}"
            )
        else:
            # Destination NAT teardown: same interface mapping as 305011
            public_iface = self._sensor_interfaces.get(sensor_hostname, {}).get(
                "_default", "outside"
            )
            real_iface = self._resolve_interface(nat.local_ip, sensor_hostname)
            message = (
                f"Teardown {nat_label} {proto_upper} translation from "
                f"{public_iface}:{nat.global_ip}/{nat.global_port} to "
                f"{real_iface}:{nat.local_ip}/{nat.local_port} "
                f"duration {duration}"
            )
        event_data = {
            "timestamp": teardown_ts,
            "hostname": fw_hostname,
            "severity": 6,
            "msg_id": 305012,
            "message": message,
            "pri": self._pri(6),
            "_sensor_hostnames": [sensor_hostname] if sensor_hostname else None,
        }
        self._dispatch(event_data)

    def _check_threat_detection(
        self,
        src_ip: str,
        timestamp: datetime,
        sensor_hostname: str,
        fw_hostname: str,
    ) -> None:
        """Check deny rates against threat detection thresholds; emit 733100 if exceeded.

        Models ASA basic threat detection for scanning. Both burst and average
        rates must exceed their thresholds before an alert fires. After firing,
        a cooldown period (= ASA burst period) prevents duplicate alerts.
        """
        if self._td_burst_threshold <= 0:
            return  # Threat detection disabled

        key = (sensor_hostname, src_ip)

        # Track this deny
        timestamps = self._deny_timestamps.setdefault(key, deque())
        timestamps.append(timestamp)

        # Keep only the data needed for active burst/average windows.
        # This bounds memory growth for sustained deny traffic.
        max_window = max(self._td_burst_window, self._td_avg_window)
        max_cutoff = timestamp - timedelta(seconds=max_window)
        while timestamps and timestamps[0] < max_cutoff:
            timestamps.popleft()

        # Cooldown check: don't fire more than once per burst period
        last_alert = self._last_alert_time.get(key)
        if last_alert and (timestamp - last_alert).total_seconds() < self._td_cooldown:
            return

        # Calculate burst rate (drops in last burst_window seconds)
        burst_cutoff = timestamp - timedelta(seconds=self._td_burst_window)
        avg_cutoff = timestamp - timedelta(seconds=self._td_avg_window)
        burst_count = 0
        avg_count = 0
        for deny_ts in timestamps:
            if deny_ts >= avg_cutoff:
                avg_count += 1
            if deny_ts >= burst_cutoff:
                burst_count += 1
        burst_rate = burst_count / self._td_burst_window
        avg_rate = avg_count / self._td_avg_window

        # Both rates must exceed thresholds (matching real ASA behavior)
        if burst_rate < self._td_burst_threshold or avg_rate < self._td_avg_threshold:
            return

        # Fire 733100
        self._last_alert_time[key] = timestamp
        total_count = len(timestamps)

        message = (
            f"[Scanning] drop rate-1 exceeded. "
            f"Current burst rate is {int(burst_rate)} per second, "
            f"max configured rate is {self._td_burst_threshold}; "
            f"Current average rate is {int(avg_rate)} per second, "
            f"max configured rate is {self._td_avg_threshold}; "
            f"Cumulative total count is {total_count}"
        )
        event_data = {
            "timestamp": timestamp,
            "hostname": fw_hostname,
            "severity": 4,
            "msg_id": 733100,
            "message": message,
            "pri": self._pri(4),
            "_sensor_hostnames": [sensor_hostname] if sensor_hostname else None,
        }
        self._dispatch(event_data)

    def _dispatch(self, event_data: dict[str, Any]) -> None:
        """Render and route to sensor writers.

        Overrides the base class _dispatch to skip Zeek UID derivation
        (firewalls don't use UIDs).
        """
        sensor_hostnames = event_data.pop("_sensor_hostnames", None)
        rendered = self._render_event(event_data)
        if rendered is None:
            return
        targets = sensor_hostnames if sensor_hostnames else self._sensor_hostnames
        if not targets:
            self.emit_to_sensors(rendered, None)
            return
        if self.output_target == OutputTarget.SOF_ELK:
            route_targets = [
                make_syslog_family_route_key(
                    sensor_hostname,
                    event_data["timestamp"],
                    direct_file_mode=self._direct_file_mode,
                )
                for sensor_hostname in targets
            ]
        else:
            route_targets = targets
        self.emit_to_sensors(rendered, route_targets)

    def _render_event(self, event_data: dict[str, Any]) -> str | None:
        """Render ASA syslog line via the shared RFC3164 syslog-family layer."""
        severity = bounded_syslog_int(
            event_data.get("severity", 6), default=6, minimum=0, maximum=7
        )
        pri = bounded_syslog_int(
            event_data.get("pri"),
            default=self._pri(severity),
            minimum=0,
            maximum=191,
        )
        return render_rfc3164_syslog(
            pri=pri,
            timestamp=event_data["timestamp"],
            hostname=str(event_data.get("hostname") or ""),
            app_name=f"%ASA-{severity}-{event_data.get('msg_id')}",
            message=str(event_data.get("message") or ""),
        )
