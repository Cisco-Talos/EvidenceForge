# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Plan frozen per-sensor observations from canonical network transactions."""

from __future__ import annotations

import hashlib
import hmac
import math
import random
import secrets
import string
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Protocol

from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    FileSensorObservation,
    NatSensorObservation,
    NetworkSensorObservation,
    NetworkTrafficLedger,
    NetworkTransactionPlan,
    NetworkTuple,
)
from evidenceforge.generation.activity.timing_profiles import (
    FirewallObservationTiming,
    NetworkSensorObservationTiming,
    firewall_observation_timing,
    get_timing_window,
    network_sensor_observation_timing,
)
from evidenceforge.generation.activity.tls_realism import certificate_file_size
from evidenceforge.generation.source_timing import (
    SourceTimingPlan,
    SourceTimingPlanner,
    SourceTimingPlanningRuntime,
    active_source_timing_planning_runtime,
)
from evidenceforge.generation.timing import (
    ClockWanderSpec,
    ConstantDistribution,
    SourceClockKey,
    SourceClockSpec,
    TimingDistributionError,
    TimingRuntime,
    TimingScope,
    TriangularDistribution,
    TruncatedLognormalDistribution,
)
from evidenceforge.utils.ids import _has_synthetic_marker
from evidenceforge.utils.rng import _stable_seed
from evidenceforge.utils.time import ensure_utc

if TYPE_CHECKING:
    from evidenceforge.events.base import CanonicalOccurrence
    from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
    from evidenceforge.models.scenario import NetworkSensor


def derive_sensor_identifier(canonical_id: str, sensor_identity: str) -> str:
    """Return a stable source-local Zeek-style identifier."""

    if not canonical_id:
        return canonical_id
    base62 = string.ascii_uppercase + string.ascii_lowercase + string.digits
    prefix = canonical_id[0]
    target_len = max(0, len(canonical_id) - 1)
    candidate = canonical_id
    for counter in range(16):
        suffix = "" if counter == 0 else f":{counter}"
        digest = hashlib.sha256(f"{canonical_id}:{sensor_identity}{suffix}".encode()).digest()
        candidate = prefix + "".join(base62[byte % 62] for byte in digest[:target_len])
        if not _has_synthetic_marker(candidate):
            return candidate
    return candidate


def network_source_timing_key(format_name: str, object_id: str = "") -> str:
    """Return the immutable key for one sensor-native network row."""

    return format_name if not object_id else f"{format_name}:{object_id}"


_PERSISTENT_SMB_MAX_SCALAR = (1 << 63) - 1
_PERSISTENT_SMB_MAX_TEXT_CHARACTERS = 4_096
_PERSISTENT_SMB_MAX_TEXT_BYTES = 4_096
_PERSISTENT_SMB_MAX_OBSERVATIONS = 4_096
_PERSISTENT_SMB_MAX_ITEMS = 16_384
_PERSISTENT_SMB_MAX_AGGREGATE_ITEMS = 65_536
_PERSISTENT_SMB_MAX_AGGREGATE_TEXT_BYTES = 8 * 1_024 * 1_024
_PERSISTENT_SMB_MAX_AGGREGATE_WORK_UNITS = 524_288
_PERSISTENT_SMB_TCP_HISTORY_MARKERS = frozenset("SsHhAaDdFfRrCcGgTtWwIiQq^")

_DIRECTIONAL_TRAFFIC_FIELDS = ("payload_bytes", "packets", "ip_bytes")
_NETWORK_TRAFFIC_FIELDS = ("orig", "resp", "missed_orig_bytes", "missed_resp_bytes")
_NETWORK_TUPLE_FIELDS = ("src_ip", "src_port", "dst_ip", "dst_port", "protocol")
_NAT_OBSERVATION_FIELDS = (
    "nat_type",
    "direction",
    "local_ip",
    "local_port",
    "global_ip",
    "global_port",
    "built_time",
    "teardown_time",
)
_FILE_OBSERVATION_FIELDS = (
    "canonical_id",
    "seen_bytes",
    "total_bytes",
    "missing_bytes",
    "analyzers_visible",
)
_NETWORK_OBSERVATION_FIELDS = (
    "sensor_identity",
    "path_role",
    "capture_profile",
    "tuple_view",
    "connection_uid",
    "connection_ids",
    "file_ids",
    "local_orig",
    "local_resp",
    "observed_start_time",
    "observed_close_time",
    "traffic",
    "visible_formats",
    "history",
    "file_observations",
    "http_request_body_len",
    "http_response_body_len",
    "firewall_teardown_reason",
    "firewall_teardown_time",
    "firewall_teardown_observed",
    "nat",
    "source_times",
    "source_durations",
)
_NETWORK_TRANSACTION_FIELDS = (
    "stable_id",
    "hostname",
    "outcome",
    "phase_times",
    "started_at",
    "closed_at",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "service",
    "zeek_uid",
    "conn_id",
    "duration",
    "conn_state",
    "history",
    "traffic",
    "initiating_pid",
    "responding_pid",
    "local_orig",
    "local_resp",
    "ip_proto",
    "link_local",
    "application_layer_only",
)
_PERSISTENT_SMB_BINDING_FIELDS = (
    "authority_id",
    "binding_id",
    "transport_digest",
    "observation_digests",
    "lossless_ordinals",
    "_integrity",
)


def _persistent_smb_schema_preflight() -> None:
    """Default-deny any unreviewed field added to a rebound dataclass."""

    schemas = (
        (DirectionalTrafficLedger, _DIRECTIONAL_TRAFFIC_FIELDS),
        (NetworkTrafficLedger, _NETWORK_TRAFFIC_FIELDS),
        (NetworkTuple, _NETWORK_TUPLE_FIELDS),
        (NatSensorObservation, _NAT_OBSERVATION_FIELDS),
        (FileSensorObservation, _FILE_OBSERVATION_FIELDS),
        (NetworkSensorObservation, _NETWORK_OBSERVATION_FIELDS),
        (NetworkTransactionPlan, _NETWORK_TRANSACTION_FIELDS),
        (PersistentSmbTrafficRebindBinding, _PERSISTENT_SMB_BINDING_FIELDS),
    )
    for model, expected in schemas:
        fields = object.__getattribute__(model, "__dataclass_fields__")
        if type(fields) is not dict:
            raise RuntimeError("Persistent SMB traffic dataclass schema changed")
        names = tuple(fields)
        if any(type(name) is not str for name in names) or names != expected:
            raise RuntimeError("Persistent SMB traffic dataclass schema changed")


def _persistent_smb_slots(value: object, model: type, names: tuple[str, ...], label: str) -> tuple:
    """Read each trusted slot exactly once after an exact carrier type gate."""

    if type(value) is not model:
        raise TypeError(f"{label} requires an exact {model.__name__}")
    return tuple(object.__getattribute__(value, name) for name in names)


def _persistent_smb_text(
    value: object,
    label: str,
    *,
    allow_empty: bool = False,
) -> str:
    if type(value) is not str:
        raise TypeError(f"{label} requires an exact string")
    if not allow_empty and not value:
        raise ValueError(f"{label} must not be empty")
    if len(value) > _PERSISTENT_SMB_MAX_TEXT_CHARACTERS:
        raise ValueError(f"{label} exceeds the persistent SMB text bound")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{label} requires valid UTF-8") from error
    if len(encoded) > _PERSISTENT_SMB_MAX_TEXT_BYTES:
        raise ValueError(f"{label} exceeds the persistent SMB text bound")
    return value


def _persistent_smb_int(
    value: object,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = _PERSISTENT_SMB_MAX_SCALAR,
) -> int:
    if type(value) is not int:
        raise TypeError(f"{label} requires an exact int")
    if value < minimum or value > maximum:
        raise ValueError(f"{label} must fit the allowed signed 63-bit range")
    return value


def _persistent_smb_bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise TypeError(f"{label} requires an exact bool")
    return value


def _persistent_smb_float(value: object, label: str) -> float:
    if type(value) is not float:
        raise TypeError(f"{label} requires an exact float")
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"{label} requires one finite non-negative float")
    return value


def _persistent_smb_datetime(value: object, label: str) -> datetime:
    if type(value) is not datetime:
        raise TypeError(f"{label} requires an exact datetime")
    if object.__getattribute__(value, "tzinfo") is not UTC:
        raise ValueError(f"{label} requires the exact UTC timezone")
    return value


def _persistent_smb_optional_datetime(value: object, label: str) -> datetime | None:
    if value is None:
        return None
    return _persistent_smb_datetime(value, label)


def _persistent_smb_validate_final_tcp_history(
    history: str,
    traffic: _PersistentSmbTrafficFacts,
    label: str,
) -> None:
    """Reject non-TCP or incomplete-SF Zeek packet-history claims."""

    if not history or any(marker not in _PERSISTENT_SMB_TCP_HISTORY_MARKERS for marker in history):
        raise ValueError(f"{label} requires a valid nonempty TCP history")
    if any(marker not in history for marker in ("S", "h", "A", "F", "f")):
        raise ValueError(f"{label} requires one complete successful TCP history")
    if traffic.orig_payload and "D" not in history:
        raise ValueError(f"{label} omits originator data claimed by its traffic ledger")
    if traffic.resp_payload and "d" not in history:
        raise ValueError(f"{label} omits responder data claimed by its traffic ledger")


def _persistent_smb_source_key_is_visible(key: str, formats: tuple[str, ...]) -> bool:
    """Return whether one canonical source key belongs to a visible format family."""

    if key != key.strip():
        return False
    for format_name in formats:
        if key == format_name:
            return True
        prefix = f"{format_name}:"
        if key.startswith(prefix) and len(key) > len(prefix):
            return True
    return False


def _persistent_smb_utf8_size(value: str, label: str) -> int:
    """Count exact UTF-8 bytes without allocating an encoded copy."""

    if len(value) > _PERSISTENT_SMB_MAX_TEXT_CHARACTERS:
        raise ValueError(f"{label} exceeds the persistent SMB text bound")
    size = 0
    for character in value:
        codepoint = ord(character)
        if codepoint <= 0x7F:
            size += 1
        elif codepoint <= 0x7FF:
            size += 2
        elif 0xD800 <= codepoint <= 0xDFFF:
            raise ValueError(f"{label} requires valid UTF-8")
        elif codepoint <= 0xFFFF:
            size += 3
        else:
            size += 4
    if size > _PERSISTENT_SMB_MAX_TEXT_BYTES:
        raise ValueError(f"{label} exceeds the persistent SMB text bound")
    return size


@dataclass(slots=True)
class _PersistentSmbAggregateBudget:
    """Bound one complete preflight before any projection copy or digest."""

    items: int = 0
    text_bytes: int = 0
    work_units: int = 0

    def consume_items(self, count: int) -> None:
        self.items += count
        if self.items > _PERSISTENT_SMB_MAX_AGGREGATE_ITEMS:
            raise ValueError("Persistent SMB aggregate item budget exceeded")

    def consume_work(self, count: int = 1) -> None:
        self.work_units += count
        if self.work_units > _PERSISTENT_SMB_MAX_AGGREGATE_WORK_UNITS:
            raise ValueError("Persistent SMB aggregate work budget exceeded")

    def consume_text(self, value: object, label: str, *, allow_empty: bool = False) -> None:
        self.consume_work()
        if type(value) is not str:
            raise TypeError(f"{label} requires an exact string")
        if not allow_empty and not value:
            raise ValueError(f"{label} must not be empty")
        self.text_bytes += _persistent_smb_utf8_size(value, label)
        if self.text_bytes > _PERSISTENT_SMB_MAX_AGGREGATE_TEXT_BYTES:
            raise ValueError("Persistent SMB aggregate encoded-byte budget exceeded")


def _preflight_persistent_smb_traffic(
    value: object,
    label: str,
    budget: _PersistentSmbAggregateBudget,
) -> None:
    if type(value) is not NetworkTrafficLedger:
        raise TypeError(f"{label} requires an exact NetworkTrafficLedger")
    budget.consume_work(len(_NETWORK_TRAFFIC_FIELDS))
    orig = object.__getattribute__(value, "orig")
    resp = object.__getattribute__(value, "resp")
    missed_orig = object.__getattribute__(value, "missed_orig_bytes")
    missed_resp = object.__getattribute__(value, "missed_resp_bytes")
    for direction_name, direction in (("orig", orig), ("resp", resp)):
        if type(direction) is not DirectionalTrafficLedger:
            raise TypeError(f"{label}.{direction_name} requires an exact DirectionalTrafficLedger")
        budget.consume_work(len(_DIRECTIONAL_TRAFFIC_FIELDS))
        _persistent_smb_int(
            object.__getattribute__(direction, "payload_bytes"),
            f"{label}.{direction_name}.payload_bytes",
        )
        _persistent_smb_int(
            object.__getattribute__(direction, "packets"),
            f"{label}.{direction_name}.packets",
        )
        _persistent_smb_int(
            object.__getattribute__(direction, "ip_bytes"),
            f"{label}.{direction_name}.ip_bytes",
        )
    _persistent_smb_int(missed_orig, f"{label}.missed_orig_bytes")
    _persistent_smb_int(missed_resp, f"{label}.missed_resp_bytes")


def _preflight_persistent_smb_text_pairs(
    value: object,
    label: str,
    budget: _PersistentSmbAggregateBudget,
) -> None:
    budget.consume_work()
    if type(value) is not tuple:
        raise TypeError(f"{label} requires an exact tuple")
    count = len(value)
    if count > _PERSISTENT_SMB_MAX_ITEMS:
        raise ValueError(f"{label} exceeds the persistent SMB item bound")
    budget.consume_items(count)
    for ordinal, pair in enumerate(value):
        budget.consume_work()
        if type(pair) is not tuple or len(pair) != 2:
            raise TypeError(f"{label}[{ordinal}] requires one exact pair")
        budget.consume_items(2)
        budget.consume_text(tuple.__getitem__(pair, 0), f"{label}[{ordinal}][0]")
        budget.consume_text(tuple.__getitem__(pair, 1), f"{label}[{ordinal}][1]")


def _preflight_persistent_smb_time_pairs(
    value: object,
    label: str,
    budget: _PersistentSmbAggregateBudget,
) -> None:
    budget.consume_work()
    if type(value) is not tuple:
        raise TypeError(f"{label} requires an exact tuple")
    count = len(value)
    if count > _PERSISTENT_SMB_MAX_ITEMS:
        raise ValueError(f"{label} exceeds the persistent SMB item bound")
    budget.consume_items(count)
    for ordinal, pair in enumerate(value):
        budget.consume_work()
        if type(pair) is not tuple or len(pair) != 2:
            raise TypeError(f"{label}[{ordinal}] requires one exact pair")
        budget.consume_items(2)
        budget.consume_text(tuple.__getitem__(pair, 0), f"{label}[{ordinal}].key")
        _persistent_smb_datetime(
            tuple.__getitem__(pair, 1),
            f"{label}[{ordinal}].timestamp",
        )


def _preflight_persistent_smb_duration_pairs(
    value: object,
    label: str,
    budget: _PersistentSmbAggregateBudget,
) -> None:
    budget.consume_work()
    if type(value) is not tuple:
        raise TypeError(f"{label} requires an exact tuple")
    count = len(value)
    if count > _PERSISTENT_SMB_MAX_ITEMS:
        raise ValueError(f"{label} exceeds the persistent SMB item bound")
    budget.consume_items(count)
    for ordinal, pair in enumerate(value):
        budget.consume_work()
        if type(pair) is not tuple or len(pair) != 2:
            raise TypeError(f"{label}[{ordinal}] requires one exact pair")
        budget.consume_items(2)
        budget.consume_text(tuple.__getitem__(pair, 0), f"{label}[{ordinal}].key")
        _persistent_smb_float(
            tuple.__getitem__(pair, 1),
            f"{label}[{ordinal}].duration",
        )


def _preflight_persistent_smb_tuple(
    value: object,
    label: str,
    budget: _PersistentSmbAggregateBudget,
) -> None:
    if type(value) is not NetworkTuple:
        raise TypeError(f"{label} requires an exact NetworkTuple")
    budget.consume_work(len(_NETWORK_TUPLE_FIELDS))
    budget.consume_text(object.__getattribute__(value, "src_ip"), f"{label}.src_ip")
    _persistent_smb_int(
        object.__getattribute__(value, "src_port"),
        f"{label}.src_port",
        minimum=1,
        maximum=65_535,
    )
    budget.consume_text(object.__getattribute__(value, "dst_ip"), f"{label}.dst_ip")
    _persistent_smb_int(
        object.__getattribute__(value, "dst_port"),
        f"{label}.dst_port",
        minimum=1,
        maximum=65_535,
    )
    budget.consume_text(object.__getattribute__(value, "protocol"), f"{label}.protocol")


def _preflight_persistent_smb_nat(
    value: object,
    label: str,
    budget: _PersistentSmbAggregateBudget,
) -> None:
    if type(value) is not NatSensorObservation:
        raise TypeError(f"{label} requires an exact NatSensorObservation")
    budget.consume_work(len(_NAT_OBSERVATION_FIELDS))
    for name in ("nat_type", "direction", "local_ip", "global_ip"):
        budget.consume_text(
            object.__getattribute__(value, name),
            f"{label}.{name}",
        )
    for name in ("local_port", "global_port"):
        _persistent_smb_int(
            object.__getattribute__(value, name),
            f"{label}.{name}",
            minimum=1,
            maximum=65_535,
        )
    _persistent_smb_datetime(object.__getattribute__(value, "built_time"), f"{label}.built_time")
    _persistent_smb_optional_datetime(
        object.__getattribute__(value, "teardown_time"),
        f"{label}.teardown_time",
    )


def _preflight_persistent_smb_transport(
    value: object,
    budget: _PersistentSmbAggregateBudget,
) -> None:
    if type(value) is not NetworkTransactionPlan:
        raise TypeError("transport requires an exact NetworkTransactionPlan")
    budget.consume_work(len(_NETWORK_TRANSACTION_FIELDS))
    for name, allow_empty in (
        ("stable_id", False),
        ("hostname", True),
        ("outcome", False),
        ("src_ip", False),
        ("dst_ip", False),
        ("protocol", False),
        ("service", False),
        ("zeek_uid", False),
        ("conn_id", False),
        ("conn_state", False),
        ("history", False),
    ):
        budget.consume_text(
            object.__getattribute__(value, name),
            f"transport.{name}",
            allow_empty=allow_empty,
        )
    _preflight_persistent_smb_time_pairs(
        object.__getattribute__(value, "phase_times"),
        "transport.phase_times",
        budget,
    )
    _persistent_smb_datetime(
        object.__getattribute__(value, "started_at"),
        "transport.started_at",
    )
    _persistent_smb_optional_datetime(
        object.__getattribute__(value, "closed_at"),
        "transport.closed_at",
    )
    for name in ("src_port", "dst_port"):
        _persistent_smb_int(
            object.__getattribute__(value, name),
            f"transport.{name}",
            minimum=1,
            maximum=65_535,
        )
    duration = object.__getattribute__(value, "duration")
    if duration is not None:
        _persistent_smb_float(duration, "transport.duration")
    _preflight_persistent_smb_traffic(
        object.__getattribute__(value, "traffic"),
        "transport.traffic",
        budget,
    )
    for name in ("initiating_pid", "responding_pid"):
        _persistent_smb_int(
            object.__getattribute__(value, name),
            f"transport.{name}",
            minimum=-1,
        )
    for name in ("local_orig", "local_resp", "link_local", "application_layer_only"):
        _persistent_smb_bool(object.__getattribute__(value, name), f"transport.{name}")
    _persistent_smb_int(
        object.__getattribute__(value, "ip_proto"),
        "transport.ip_proto",
        maximum=255,
    )


def _preflight_persistent_smb_observation(
    value: object,
    ordinal: int,
    budget: _PersistentSmbAggregateBudget,
) -> None:
    label = f"observations[{ordinal}]"
    if type(value) is not NetworkSensorObservation:
        raise TypeError(f"{label} requires an exact NetworkSensorObservation")
    budget.consume_work(len(_NETWORK_OBSERVATION_FIELDS))
    for name, allow_empty in (
        ("sensor_identity", False),
        ("path_role", False),
        ("capture_profile", False),
        ("connection_uid", False),
        ("history", False),
        ("firewall_teardown_reason", True),
    ):
        budget.consume_text(
            object.__getattribute__(value, name),
            f"{label}.{name}",
            allow_empty=allow_empty,
        )
    _preflight_persistent_smb_tuple(
        object.__getattribute__(value, "tuple_view"),
        f"{label}.tuple_view",
        budget,
    )
    _preflight_persistent_smb_text_pairs(
        object.__getattribute__(value, "connection_ids"),
        f"{label}.connection_ids",
        budget,
    )
    for name in ("file_ids", "file_observations"):
        derivative = object.__getattribute__(value, name)
        budget.consume_work()
        if type(derivative) is not tuple:
            raise TypeError(f"{label}.{name} requires an exact tuple")
        budget.consume_items(len(derivative))
        if derivative:
            raise ValueError(
                "Persistent traffic rebinding requires an SMB-neutral observation shape"
            )
    for name in ("http_request_body_len", "http_response_body_len"):
        budget.consume_work()
        if object.__getattribute__(value, name) is not None:
            raise ValueError(
                "Persistent traffic rebinding requires an SMB-neutral observation shape"
            )
    for name in ("local_orig", "local_resp", "firewall_teardown_observed"):
        _persistent_smb_bool(object.__getattribute__(value, name), f"{label}.{name}")
    _persistent_smb_datetime(
        object.__getattribute__(value, "observed_start_time"),
        f"{label}.observed_start_time",
    )
    _persistent_smb_optional_datetime(
        object.__getattribute__(value, "observed_close_time"),
        f"{label}.observed_close_time",
    )
    _preflight_persistent_smb_traffic(
        object.__getattribute__(value, "traffic"),
        f"{label}.traffic",
        budget,
    )
    formats = object.__getattribute__(value, "visible_formats")
    budget.consume_work()
    if type(formats) is not frozenset:
        raise TypeError(f"{label}.visible_formats requires an exact frozenset")
    if len(formats) > _PERSISTENT_SMB_MAX_ITEMS:
        raise ValueError(f"{label}.visible_formats exceeds the persistent SMB item bound")
    budget.consume_items(len(formats))
    for format_name in formats:
        budget.consume_text(format_name, f"{label}.visible_formats item")
    _persistent_smb_optional_datetime(
        object.__getattribute__(value, "firewall_teardown_time"),
        f"{label}.firewall_teardown_time",
    )
    nat = object.__getattribute__(value, "nat")
    if nat is not None:
        _preflight_persistent_smb_nat(nat, f"{label}.nat", budget)
    _preflight_persistent_smb_time_pairs(
        object.__getattribute__(value, "source_times"),
        f"{label}.source_times",
        budget,
    )
    _preflight_persistent_smb_duration_pairs(
        object.__getattribute__(value, "source_durations"),
        f"{label}.source_durations",
        budget,
    )


def _preflight_persistent_smb_observation_cohort(
    observations: object,
    budget: _PersistentSmbAggregateBudget,
) -> None:
    budget.consume_work()
    if type(observations) is not tuple:
        raise TypeError("Persistent SMB observations require an exact tuple")
    count = len(observations)
    if count > _PERSISTENT_SMB_MAX_OBSERVATIONS:
        raise ValueError("Persistent SMB observations exceed their cohort bound")
    budget.consume_items(count)
    for ordinal, observation in enumerate(observations):
        _preflight_persistent_smb_observation(observation, ordinal, budget)


def _preflight_persistent_smb_binding(
    value: object,
    budget: _PersistentSmbAggregateBudget,
) -> None:
    if type(value) is not PersistentSmbTrafficRebindBinding:
        raise TypeError("binding requires an exact PersistentSmbTrafficRebindBinding")
    budget.consume_work(len(_PERSISTENT_SMB_BINDING_FIELDS))
    for name in ("authority_id", "binding_id", "transport_digest", "_integrity"):
        budget.consume_text(object.__getattribute__(value, name), f"binding.{name}")
    digests = object.__getattribute__(value, "observation_digests")
    if type(digests) is not tuple or len(digests) > _PERSISTENT_SMB_MAX_OBSERVATIONS:
        raise TypeError("binding.observation_digests requires one bounded exact tuple")
    budget.consume_items(len(digests))
    for digest in digests:
        budget.consume_text(digest, "binding observation digest")
    ordinals = object.__getattribute__(value, "lossless_ordinals")
    if type(ordinals) is not tuple or len(ordinals) > _PERSISTENT_SMB_MAX_OBSERVATIONS:
        raise TypeError("binding.lossless_ordinals requires one bounded exact tuple")
    budget.consume_items(len(ordinals))
    for ordinal in ordinals:
        budget.consume_work()
        _persistent_smb_int(
            ordinal,
            "binding lossless ordinal",
            maximum=max(0, len(digests) - 1),
        )


def _preflight_persistent_smb_opening(
    transport: object,
    observations: object,
) -> None:
    budget = _PersistentSmbAggregateBudget()
    _preflight_persistent_smb_transport(transport, budget)
    _preflight_persistent_smb_observation_cohort(observations, budget)


def _preflight_persistent_smb_close_inputs(
    binding: object,
    transport: object,
    final_traffic: object,
    observations: object,
    final_observation_traffic: object,
) -> None:
    budget = _PersistentSmbAggregateBudget()
    _preflight_persistent_smb_binding(binding, budget)
    _preflight_persistent_smb_transport(transport, budget)
    _preflight_persistent_smb_observation_cohort(observations, budget)
    _preflight_persistent_smb_traffic(final_traffic, "final_traffic", budget)
    budget.consume_work()
    if type(final_observation_traffic) is not tuple:
        raise TypeError("Persistent final observation traffic requires an exact tuple")
    count = len(final_observation_traffic)
    if count > _PERSISTENT_SMB_MAX_OBSERVATIONS:
        raise ValueError("Persistent final observation traffic exceeds its cohort bound")
    budget.consume_items(count)
    for ordinal, traffic in enumerate(final_observation_traffic):
        _preflight_persistent_smb_traffic(
            traffic,
            f"final_observation_traffic[{ordinal}]",
            budget,
        )


def _preflight_persistent_smb_close_facts(
    binding: object,
    final_traffic: object,
    final_observation_traffic: object,
) -> None:
    budget = _PersistentSmbAggregateBudget()
    _preflight_persistent_smb_binding(binding, budget)
    _preflight_persistent_smb_traffic(final_traffic, "final_traffic", budget)
    budget.consume_work()
    if type(final_observation_traffic) is not tuple:
        raise TypeError("Persistent final observation traffic requires an exact tuple")
    count = len(final_observation_traffic)
    if count > _PERSISTENT_SMB_MAX_OBSERVATIONS:
        raise ValueError("Persistent final observation traffic exceeds its cohort bound")
    budget.consume_items(count)
    for ordinal, traffic in enumerate(final_observation_traffic):
        _preflight_persistent_smb_traffic(
            traffic,
            f"final_observation_traffic[{ordinal}]",
            budget,
        )


@dataclass(frozen=True, slots=True)
class _PersistentSmbTrafficFacts:
    orig_payload: int
    orig_packets: int
    orig_ip: int
    resp_payload: int
    resp_packets: int
    resp_ip: int
    missed_orig: int
    missed_resp: int

    def materialize(self) -> NetworkTrafficLedger:
        return NetworkTrafficLedger(
            orig=DirectionalTrafficLedger(self.orig_payload, self.orig_packets, self.orig_ip),
            resp=DirectionalTrafficLedger(self.resp_payload, self.resp_packets, self.resp_ip),
            missed_orig_bytes=self.missed_orig,
            missed_resp_bytes=self.missed_resp,
        )


@dataclass(frozen=True, slots=True)
class _PersistentSmbTupleFacts:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str

    def materialize(self) -> NetworkTuple:
        return NetworkTuple(
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
            self.protocol,
        )


@dataclass(frozen=True, slots=True)
class _PersistentSmbNatFacts:
    nat_type: str
    direction: str
    local_ip: str
    local_port: int
    global_ip: str
    global_port: int
    built_time: datetime
    teardown_time: datetime | None

    def materialize(self) -> NatSensorObservation:
        return NatSensorObservation(
            nat_type=self.nat_type,
            direction=self.direction,
            local_ip=self.local_ip,
            local_port=self.local_port,
            global_ip=self.global_ip,
            global_port=self.global_port,
            built_time=self.built_time,
            teardown_time=self.teardown_time,
        )


@dataclass(frozen=True, slots=True)
class _PersistentSmbTransportFacts:
    stable_id: str
    hostname: str
    outcome: str
    phase_times: tuple[tuple[str, datetime], ...]
    started_at: datetime
    closed_at: datetime | None
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    service: str
    zeek_uid: str
    conn_id: str
    duration: float | None
    conn_state: str
    history: str
    traffic: _PersistentSmbTrafficFacts
    initiating_pid: int = -1
    responding_pid: int = -1
    local_orig: bool = True
    local_resp: bool = False
    ip_proto: int = 6
    link_local: bool = False
    application_layer_only: bool = False


@dataclass(frozen=True, slots=True)
class _PersistentSmbObservationFacts:
    sensor_identity: str
    path_role: str
    capture_profile: str
    tuple_view: _PersistentSmbTupleFacts
    connection_uid: str
    connection_ids: tuple[tuple[str, str], ...]
    local_orig: bool
    local_resp: bool
    observed_start_time: datetime
    observed_close_time: datetime | None
    traffic: _PersistentSmbTrafficFacts
    visible_formats: tuple[str, ...] = ()
    history: str = ""
    firewall_teardown_reason: str = ""
    firewall_teardown_time: datetime | None = None
    firewall_teardown_observed: bool = True
    nat: _PersistentSmbNatFacts | None = None
    source_times: tuple[tuple[str, datetime], ...] = ()
    source_durations: tuple[tuple[str, float], ...] = ()


@dataclass(frozen=True, slots=True)
class PersistentSmbTrafficRebindBinding:
    """Signed scalar binding for one SMB transport and ordered sensor cohort."""

    authority_id: str
    binding_id: str
    transport_digest: str
    observation_digests: tuple[str, ...]
    lossless_ordinals: tuple[int, ...]
    _integrity: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class _PersistentSmbBindingFacts:
    authority_id: str
    binding_id: str
    transport_digest: str
    observation_digests: tuple[str, ...]
    lossless_ordinals: tuple[int, ...]
    integrity: str


class _PersistentSmbTrafficCloseProofAuthenticator(Protocol):
    """Trusted future dispatcher interface for its exact frozen opaque proof.

    Implementations authenticate the retained State terminal result/receipt and
    the dispatcher-owned ordered sensor projection. This module never issues
    that proof and invokes the trusted callback only after bounded snapshots are
    complete, outside every lock.
    """

    def authenticates_persistent_smb_close_proof(
        self,
        proof: object,
        binding_id: str,
        close_facts_digest: str,
    ) -> bool: ...


def _snapshot_persistent_smb_traffic(
    value: object,
    label: str,
    budget: _PersistentSmbAggregateBudget | None = None,
) -> tuple[_PersistentSmbTrafficFacts, NetworkTrafficLedger]:
    orig, resp, missed_orig, missed_resp = _persistent_smb_slots(
        value,
        NetworkTrafficLedger,
        _NETWORK_TRAFFIC_FIELDS,
        label,
    )
    if type(orig) is not DirectionalTrafficLedger:
        raise TypeError(f"{label}.orig requires an exact DirectionalTrafficLedger")
    if type(resp) is not DirectionalTrafficLedger:
        raise TypeError(f"{label}.resp requires an exact DirectionalTrafficLedger")
    orig_payload, orig_packets, orig_ip = _persistent_smb_slots(
        orig,
        DirectionalTrafficLedger,
        _DIRECTIONAL_TRAFFIC_FIELDS,
        f"{label}.orig",
    )
    resp_payload, resp_packets, resp_ip = _persistent_smb_slots(
        resp,
        DirectionalTrafficLedger,
        _DIRECTIONAL_TRAFFIC_FIELDS,
        f"{label}.resp",
    )
    if budget is not None:
        budget.consume_work(len(_NETWORK_TRAFFIC_FIELDS) + 2 * len(_DIRECTIONAL_TRAFFIC_FIELDS))
    checked = (
        _persistent_smb_int(orig_payload, f"{label}.orig.payload_bytes"),
        _persistent_smb_int(orig_packets, f"{label}.orig.packets"),
        _persistent_smb_int(orig_ip, f"{label}.orig.ip_bytes"),
        _persistent_smb_int(resp_payload, f"{label}.resp.payload_bytes"),
        _persistent_smb_int(resp_packets, f"{label}.resp.packets"),
        _persistent_smb_int(resp_ip, f"{label}.resp.ip_bytes"),
        _persistent_smb_int(missed_orig, f"{label}.missed_orig_bytes"),
        _persistent_smb_int(missed_resp, f"{label}.missed_resp_bytes"),
    )
    facts = _PersistentSmbTrafficFacts(*checked)
    for direction, payload, packets, ip_bytes in (
        ("orig", facts.orig_payload, facts.orig_packets, facts.orig_ip),
        ("resp", facts.resp_payload, facts.resp_packets, facts.resp_ip),
    ):
        if ip_bytes < payload:
            raise ValueError(f"{label}.{direction} IP bytes cannot be smaller than payload")
        if packets == 0 and ip_bytes != 0:
            raise ValueError(f"{label}.{direction} IP bytes require at least one packet")
        if packets != 0 and ip_bytes > packets * 1_500:
            raise ValueError(f"{label}.{direction} IP bytes exceed the TCP MTU proof")
    return facts, value


def _snapshot_persistent_smb_tuple(
    value: object,
    label: str,
    budget: _PersistentSmbAggregateBudget | None = None,
) -> _PersistentSmbTupleFacts:
    src_ip, src_port, dst_ip, dst_port, protocol = _persistent_smb_slots(
        value,
        NetworkTuple,
        _NETWORK_TUPLE_FIELDS,
        label,
    )
    if budget is not None:
        budget.consume_work(len(_NETWORK_TUPLE_FIELDS))
        budget.consume_text(src_ip, f"{label}.src_ip")
        budget.consume_text(dst_ip, f"{label}.dst_ip")
        budget.consume_text(protocol, f"{label}.protocol")
    facts = _PersistentSmbTupleFacts(
        src_ip=_persistent_smb_text(src_ip, f"{label}.src_ip"),
        src_port=_persistent_smb_int(
            src_port,
            f"{label}.src_port",
            minimum=1,
            maximum=65_535,
        ),
        dst_ip=_persistent_smb_text(dst_ip, f"{label}.dst_ip"),
        dst_port=_persistent_smb_int(
            dst_port,
            f"{label}.dst_port",
            minimum=1,
            maximum=65_535,
        ),
        protocol=_persistent_smb_text(protocol, f"{label}.protocol"),
    )
    if facts.protocol != "tcp" or facts.dst_port != 445:
        raise ValueError("Persistent SMB sensor tuples require TCP destination port 445")
    return facts


def _snapshot_persistent_smb_nat(
    value: object,
    label: str,
    budget: _PersistentSmbAggregateBudget | None = None,
) -> _PersistentSmbNatFacts:
    (
        nat_type,
        direction,
        local_ip,
        local_port,
        global_ip,
        global_port,
        built_time,
        teardown_time,
    ) = _persistent_smb_slots(value, NatSensorObservation, _NAT_OBSERVATION_FIELDS, label)
    if budget is not None:
        budget.consume_work(len(_NAT_OBSERVATION_FIELDS))
        budget.consume_text(nat_type, f"{label}.nat_type")
        budget.consume_text(direction, f"{label}.direction")
        budget.consume_text(local_ip, f"{label}.local_ip")
        budget.consume_text(global_ip, f"{label}.global_ip")
    facts = _PersistentSmbNatFacts(
        nat_type=_persistent_smb_text(nat_type, f"{label}.nat_type"),
        direction=_persistent_smb_text(direction, f"{label}.direction"),
        local_ip=_persistent_smb_text(local_ip, f"{label}.local_ip"),
        local_port=_persistent_smb_int(
            local_port,
            f"{label}.local_port",
            minimum=1,
            maximum=65_535,
        ),
        global_ip=_persistent_smb_text(global_ip, f"{label}.global_ip"),
        global_port=_persistent_smb_int(
            global_port,
            f"{label}.global_port",
            minimum=1,
            maximum=65_535,
        ),
        built_time=_persistent_smb_datetime(built_time, f"{label}.built_time"),
        teardown_time=_persistent_smb_optional_datetime(
            teardown_time,
            f"{label}.teardown_time",
        ),
    )
    if facts.nat_type not in {"dynamic_pat", "static"}:
        raise ValueError(f"{label}.nat_type is unsupported")
    if facts.direction not in {"source", "destination"}:
        raise ValueError(f"{label}.direction is unsupported")
    if facts.teardown_time is not None and facts.teardown_time < facts.built_time:
        raise ValueError(f"{label}.teardown_time precedes its build")
    return facts


def _snapshot_persistent_smb_text_pairs(
    value: object,
    label: str,
    budget: _PersistentSmbAggregateBudget | None = None,
) -> tuple[tuple[str, str], ...]:
    if type(value) is not tuple:
        raise TypeError(f"{label} requires an exact tuple")
    if len(value) > _PERSISTENT_SMB_MAX_ITEMS:
        raise ValueError(f"{label} exceeds the persistent SMB item bound")
    if budget is not None:
        budget.consume_work()
        budget.consume_items(len(value))
    result: list[tuple[str, str]] = []
    for ordinal, pair in enumerate(value):
        if type(pair) is not tuple or len(pair) != 2:
            raise TypeError(f"{label}[{ordinal}] requires one exact pair")
        first = object.__getattribute__(pair, "__getitem__")(0)
        second = object.__getattribute__(pair, "__getitem__")(1)
        if budget is not None:
            budget.consume_work()
            budget.consume_items(2)
            budget.consume_text(first, f"{label}[{ordinal}][0]")
            budget.consume_text(second, f"{label}[{ordinal}][1]")
        result.append(
            (
                _persistent_smb_text(first, f"{label}[{ordinal}][0]"),
                _persistent_smb_text(second, f"{label}[{ordinal}][1]"),
            )
        )
    return tuple(result)


def _snapshot_persistent_smb_time_pairs(
    value: object,
    label: str,
    budget: _PersistentSmbAggregateBudget | None = None,
) -> tuple[tuple[str, datetime], ...]:
    if type(value) is not tuple:
        raise TypeError(f"{label} requires an exact tuple")
    if len(value) > _PERSISTENT_SMB_MAX_ITEMS:
        raise ValueError(f"{label} exceeds the persistent SMB item bound")
    if budget is not None:
        budget.consume_work()
        budget.consume_items(len(value))
    result: list[tuple[str, datetime]] = []
    for ordinal, pair in enumerate(value):
        if type(pair) is not tuple or len(pair) != 2:
            raise TypeError(f"{label}[{ordinal}] requires one exact pair")
        key = object.__getattribute__(pair, "__getitem__")(0)
        timestamp = object.__getattribute__(pair, "__getitem__")(1)
        if budget is not None:
            budget.consume_work()
            budget.consume_items(2)
            budget.consume_text(key, f"{label}[{ordinal}].key")
        result.append(
            (
                _persistent_smb_text(key, f"{label}[{ordinal}].key"),
                _persistent_smb_datetime(timestamp, f"{label}[{ordinal}].timestamp"),
            )
        )
    return tuple(result)


def _snapshot_persistent_smb_duration_pairs(
    value: object,
    label: str,
    budget: _PersistentSmbAggregateBudget | None = None,
) -> tuple[tuple[str, float], ...]:
    if type(value) is not tuple:
        raise TypeError(f"{label} requires an exact tuple")
    if len(value) > _PERSISTENT_SMB_MAX_ITEMS:
        raise ValueError(f"{label} exceeds the persistent SMB item bound")
    if budget is not None:
        budget.consume_work()
        budget.consume_items(len(value))
    result: list[tuple[str, float]] = []
    for ordinal, pair in enumerate(value):
        if type(pair) is not tuple or len(pair) != 2:
            raise TypeError(f"{label}[{ordinal}] requires one exact pair")
        key = object.__getattribute__(pair, "__getitem__")(0)
        duration = object.__getattribute__(pair, "__getitem__")(1)
        if budget is not None:
            budget.consume_work()
            budget.consume_items(2)
            budget.consume_text(key, f"{label}[{ordinal}].key")
        result.append(
            (
                _persistent_smb_text(key, f"{label}[{ordinal}].key"),
                _persistent_smb_float(duration, f"{label}[{ordinal}].duration"),
            )
        )
    return tuple(result)


def _snapshot_persistent_smb_formats(
    value: object,
    label: str,
    budget: _PersistentSmbAggregateBudget | None = None,
) -> tuple[str, ...]:
    if type(value) is not frozenset:
        raise TypeError(f"{label} requires an exact frozenset")
    if len(value) > _PERSISTENT_SMB_MAX_ITEMS:
        raise ValueError(f"{label} exceeds the persistent SMB item bound")
    if budget is not None:
        budget.consume_work()
        budget.consume_items(len(value))
        for item in value:
            budget.consume_text(item, f"{label} item")
    checked = [_persistent_smb_text(item, f"{label} item") for item in value]
    if any(item != item.strip() or ":" in item for item in checked):
        raise ValueError(f"{label} requires canonical format names")
    return tuple(sorted(checked))


def _snapshot_persistent_smb_transport(
    value: object,
    budget: _PersistentSmbAggregateBudget | None = None,
) -> tuple[_PersistentSmbTransportFacts, NetworkTrafficLedger]:
    (
        stable_id,
        hostname,
        outcome,
        phase_times,
        started_at,
        closed_at,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol,
        service,
        zeek_uid,
        conn_id,
        duration,
        conn_state,
        history,
        traffic,
        initiating_pid,
        responding_pid,
        local_orig,
        local_resp,
        ip_proto,
        link_local,
        application_layer_only,
    ) = _persistent_smb_slots(
        value,
        NetworkTransactionPlan,
        _NETWORK_TRANSACTION_FIELDS,
        "transport",
    )
    if budget is not None:
        budget.consume_work(len(_NETWORK_TRANSACTION_FIELDS))
        for field_value, field_name, allow_empty in (
            (stable_id, "stable_id", False),
            (hostname, "hostname", True),
            (outcome, "outcome", False),
            (src_ip, "src_ip", False),
            (dst_ip, "dst_ip", False),
            (protocol, "protocol", False),
            (service, "service", False),
            (zeek_uid, "zeek_uid", False),
            (conn_id, "conn_id", False),
            (conn_state, "conn_state", False),
            (history, "history", False),
        ):
            budget.consume_text(
                field_value,
                f"transport.{field_name}",
                allow_empty=allow_empty,
            )
    traffic_facts, traffic_object = _snapshot_persistent_smb_traffic(
        traffic,
        "transport.traffic",
        budget,
    )
    checked_duration = (
        None if duration is None else _persistent_smb_float(duration, "transport.duration")
    )
    facts = _PersistentSmbTransportFacts(
        stable_id=_persistent_smb_text(stable_id, "transport.stable_id"),
        hostname=_persistent_smb_text(hostname, "transport.hostname", allow_empty=True),
        outcome=_persistent_smb_text(outcome, "transport.outcome"),
        phase_times=_snapshot_persistent_smb_time_pairs(
            phase_times,
            "transport.phase_times",
            budget,
        ),
        started_at=_persistent_smb_datetime(started_at, "transport.started_at"),
        closed_at=_persistent_smb_optional_datetime(closed_at, "transport.closed_at"),
        src_ip=_persistent_smb_text(src_ip, "transport.src_ip"),
        src_port=_persistent_smb_int(
            src_port,
            "transport.src_port",
            minimum=1,
            maximum=65_535,
        ),
        dst_ip=_persistent_smb_text(dst_ip, "transport.dst_ip"),
        dst_port=_persistent_smb_int(
            dst_port,
            "transport.dst_port",
            minimum=1,
            maximum=65_535,
        ),
        protocol=_persistent_smb_text(protocol, "transport.protocol"),
        service=_persistent_smb_text(service, "transport.service"),
        zeek_uid=_persistent_smb_text(zeek_uid, "transport.zeek_uid"),
        conn_id=_persistent_smb_text(conn_id, "transport.conn_id"),
        duration=checked_duration,
        conn_state=_persistent_smb_text(conn_state, "transport.conn_state"),
        history=_persistent_smb_text(history, "transport.history"),
        traffic=traffic_facts,
        initiating_pid=_persistent_smb_int(
            initiating_pid,
            "transport.initiating_pid",
            minimum=-1,
        ),
        responding_pid=_persistent_smb_int(
            responding_pid,
            "transport.responding_pid",
            minimum=-1,
        ),
        local_orig=_persistent_smb_bool(local_orig, "transport.local_orig"),
        local_resp=_persistent_smb_bool(local_resp, "transport.local_resp"),
        ip_proto=_persistent_smb_int(ip_proto, "transport.ip_proto", maximum=255),
        link_local=_persistent_smb_bool(link_local, "transport.link_local"),
        application_layer_only=_persistent_smb_bool(
            application_layer_only,
            "transport.application_layer_only",
        ),
    )
    if (
        facts.protocol != "tcp"
        or facts.ip_proto != 6
        or facts.dst_port != 445
        or facts.service != "smb"
        or facts.conn_state != "SF"
        or facts.outcome != "success"
    ):
        raise ValueError(
            "Persistent traffic rebinding requires one successful SMB TCP/445 transport"
        )
    if facts.application_layer_only:
        raise ValueError("Persistent traffic rebinding requires one physical SMB transport")
    _persistent_smb_validate_final_tcp_history(
        facts.history,
        facts.traffic,
        "transport.history",
    )
    if facts.traffic.resp_payload == 0 or facts.traffic.resp_packets == 0:
        raise ValueError("Persistent SMB transport requires responder payload and packet evidence")
    if facts.phase_times and facts.phase_times[0][1] != facts.started_at:
        raise ValueError("Persistent SMB transport phases must anchor the transport start")
    if any(
        later[1] < earlier[1]
        for earlier, later in zip(facts.phase_times, facts.phase_times[1:], strict=False)
    ):
        raise ValueError("Persistent SMB transport phases must be chronologically ordered")
    if facts.closed_at is None or facts.duration is None or facts.closed_at < facts.started_at:
        raise ValueError("Persistent SMB transport requires one final closed interval")
    if any(timestamp > facts.closed_at for _phase, timestamp in facts.phase_times):
        raise ValueError("Persistent SMB transport phase follows its declared close")
    if abs((facts.closed_at - facts.started_at).total_seconds() - facts.duration) > 0.000001:
        raise ValueError("Persistent SMB transport duration does not match its interval")
    return facts, traffic_object


def _snapshot_persistent_smb_observation(
    value: object,
    ordinal: int,
    budget: _PersistentSmbAggregateBudget | None = None,
) -> tuple[_PersistentSmbObservationFacts, NetworkTrafficLedger]:
    label = f"observations[{ordinal}]"
    (
        sensor_identity,
        path_role,
        capture_profile,
        tuple_view,
        connection_uid,
        connection_ids,
        file_ids,
        local_orig,
        local_resp,
        observed_start_time,
        observed_close_time,
        traffic,
        visible_formats,
        history,
        file_observations,
        http_request_body_len,
        http_response_body_len,
        firewall_teardown_reason,
        firewall_teardown_time,
        firewall_teardown_observed,
        nat,
        source_times,
        source_durations,
    ) = _persistent_smb_slots(
        value,
        NetworkSensorObservation,
        _NETWORK_OBSERVATION_FIELDS,
        label,
    )
    if budget is not None:
        budget.consume_work(len(_NETWORK_OBSERVATION_FIELDS))
        for field_value, field_name, allow_empty in (
            (sensor_identity, "sensor_identity", False),
            (path_role, "path_role", False),
            (capture_profile, "capture_profile", False),
            (connection_uid, "connection_uid", False),
            (history, "history", False),
            (firewall_teardown_reason, "firewall_teardown_reason", True),
        ):
            budget.consume_text(
                field_value,
                f"{label}.{field_name}",
                allow_empty=allow_empty,
            )
    if type(file_ids) is not tuple or type(file_observations) is not tuple:
        raise TypeError(f"{label} file derivatives require exact tuples")
    if budget is not None:
        budget.consume_items(len(file_ids))
        budget.consume_items(len(file_observations))
    if (
        file_ids
        or file_observations
        or http_request_body_len is not None
        or (http_response_body_len is not None)
    ):
        raise ValueError("Persistent traffic rebinding requires an SMB-neutral observation shape")
    traffic_facts, traffic_object = _snapshot_persistent_smb_traffic(
        traffic,
        f"{label}.traffic",
        budget,
    )
    checked_start = _persistent_smb_datetime(
        observed_start_time,
        f"{label}.observed_start_time",
    )
    checked_close = _persistent_smb_optional_datetime(
        observed_close_time,
        f"{label}.observed_close_time",
    )
    checked_teardown = _persistent_smb_optional_datetime(
        firewall_teardown_time,
        f"{label}.firewall_teardown_time",
    )
    facts = _PersistentSmbObservationFacts(
        sensor_identity=_persistent_smb_text(sensor_identity, f"{label}.sensor_identity"),
        path_role=_persistent_smb_text(path_role, f"{label}.path_role"),
        capture_profile=_persistent_smb_text(capture_profile, f"{label}.capture_profile"),
        tuple_view=_snapshot_persistent_smb_tuple(
            tuple_view,
            f"{label}.tuple_view",
            budget,
        ),
        connection_uid=_persistent_smb_text(connection_uid, f"{label}.connection_uid"),
        connection_ids=_snapshot_persistent_smb_text_pairs(
            connection_ids,
            f"{label}.connection_ids",
            budget,
        ),
        local_orig=_persistent_smb_bool(local_orig, f"{label}.local_orig"),
        local_resp=_persistent_smb_bool(local_resp, f"{label}.local_resp"),
        observed_start_time=checked_start,
        observed_close_time=checked_close,
        traffic=traffic_facts,
        visible_formats=_snapshot_persistent_smb_formats(
            visible_formats,
            f"{label}.visible_formats",
            budget,
        ),
        history=_persistent_smb_text(history, f"{label}.history"),
        firewall_teardown_reason=_persistent_smb_text(
            firewall_teardown_reason,
            f"{label}.firewall_teardown_reason",
            allow_empty=True,
        ),
        firewall_teardown_time=checked_teardown,
        firewall_teardown_observed=_persistent_smb_bool(
            firewall_teardown_observed,
            f"{label}.firewall_teardown_observed",
        ),
        nat=(None if nat is None else _snapshot_persistent_smb_nat(nat, f"{label}.nat", budget)),
        source_times=_snapshot_persistent_smb_time_pairs(
            source_times,
            f"{label}.source_times",
            budget,
        ),
        source_durations=_snapshot_persistent_smb_duration_pairs(
            source_durations,
            f"{label}.source_durations",
            budget,
        ),
    )
    if facts.sensor_identity != facts.sensor_identity.strip():
        raise ValueError(f"{label} requires a canonical sensor identity")
    if facts.observed_close_time is None:
        raise ValueError(f"{label} requires one final observed close time")
    if facts.observed_close_time < facts.observed_start_time:
        raise ValueError(f"{label} close precedes its start")
    if not facts.visible_formats:
        raise ValueError(f"{label} requires at least one visible format")
    _persistent_smb_validate_final_tcp_history(
        facts.history,
        facts.traffic,
        f"{label}.history",
    )
    if facts.firewall_teardown_time is not None and (
        facts.firewall_teardown_time < facts.observed_start_time
    ):
        raise ValueError(f"{label} firewall teardown precedes its start")
    if facts.firewall_teardown_reason and facts.firewall_teardown_time is None:
        raise ValueError(f"{label} firewall teardown reason requires a time")
    if len({key for key, _value in facts.connection_ids}) != len(facts.connection_ids):
        raise ValueError(f"{label} connection IDs must be unique")
    if len({key for key, _value in facts.source_times}) != len(facts.source_times):
        raise ValueError(f"{label} source times must be unique")
    if len({key for key, _value in facts.source_durations}) != len(facts.source_durations):
        raise ValueError(f"{label} source durations must be unique")
    source_times = {key: timestamp for key, timestamp in facts.source_times}
    for key, timestamp in facts.source_times:
        if not _persistent_smb_source_key_is_visible(key, facts.visible_formats):
            raise ValueError(f"{label} source time does not belong to a visible format")
        if timestamp < facts.observed_start_time or timestamp > facts.observed_close_time:
            raise ValueError(f"{label} source time falls outside its observation interval")
    for key, duration in facts.source_durations:
        if not _persistent_smb_source_key_is_visible(key, facts.visible_formats):
            raise ValueError(f"{label} source duration does not belong to a visible format")
        timestamp = source_times.get(key)
        if timestamp is None:
            raise ValueError(f"{label} source duration requires its exact source time")
        remaining = (facts.observed_close_time - timestamp).total_seconds()
        if duration > remaining:
            raise ValueError(f"{label} source duration exceeds its observation interval")
    if (
        facts.nat is not None
        and facts.nat.nat_type == "dynamic_pat"
        and (
            "cisco_asa" in facts.visible_formats
            and facts.nat.teardown_time != facts.firewall_teardown_time
        )
    ):
        raise ValueError(f"{label} NAT and firewall teardown lifetimes disagree")
    return facts, traffic_object


class _PersistentSmbDigestSink(Protocol):
    def update(self, data: bytes) -> None: ...

    def hexdigest(self) -> str: ...


def _persistent_smb_stream_field(sink: _PersistentSmbDigestSink, value: bytes) -> None:
    """Stream one length-framed field without assembling an aggregate payload."""

    sink.update(len(value).to_bytes(8, "big"))
    sink.update(value)


def _persistent_smb_stream_int(sink: _PersistentSmbDigestSink, value: int) -> None:
    _persistent_smb_stream_field(sink, value.to_bytes(8, "big", signed=True))


def _persistent_smb_stream_bool(sink: _PersistentSmbDigestSink, value: bool) -> None:
    _persistent_smb_stream_field(sink, b"\x01" if value else b"\x00")


def _persistent_smb_stream_text(sink: _PersistentSmbDigestSink, value: str) -> None:
    _persistent_smb_stream_field(sink, value.encode("utf-8"))


def _persistent_smb_stream_datetime(
    sink: _PersistentSmbDigestSink,
    value: datetime,
) -> None:
    for component in (
        value.year,
        value.month,
        value.day,
        value.hour,
        value.minute,
        value.second,
        value.microsecond,
        value.fold,
    ):
        _persistent_smb_stream_int(sink, component)


def _persistent_smb_stream_optional_datetime(
    sink: _PersistentSmbDigestSink,
    value: datetime | None,
) -> None:
    _persistent_smb_stream_bool(sink, value is not None)
    if value is not None:
        _persistent_smb_stream_datetime(sink, value)


def _persistent_smb_stream_traffic(
    sink: _PersistentSmbDigestSink,
    value: _PersistentSmbTrafficFacts,
) -> None:
    for component in (
        value.orig_payload,
        value.orig_packets,
        value.orig_ip,
        value.resp_payload,
        value.resp_packets,
        value.resp_ip,
        value.missed_orig,
        value.missed_resp,
    ):
        _persistent_smb_stream_int(sink, component)


def _persistent_smb_stream_time_pairs(
    sink: _PersistentSmbDigestSink,
    value: tuple[tuple[str, datetime], ...],
) -> None:
    _persistent_smb_stream_int(sink, len(value))
    for key, timestamp in value:
        _persistent_smb_stream_text(sink, key)
        _persistent_smb_stream_datetime(sink, timestamp)


def _persistent_smb_transport_digest(value: _PersistentSmbTransportFacts) -> str:
    digest = hashlib.sha256()
    _persistent_smb_stream_field(digest, b"persistent-smb-traffic-transport-v2")
    _persistent_smb_stream_text(digest, value.stable_id)
    _persistent_smb_stream_text(digest, value.hostname)
    _persistent_smb_stream_text(digest, value.outcome)
    _persistent_smb_stream_time_pairs(digest, value.phase_times)
    _persistent_smb_stream_datetime(digest, value.started_at)
    _persistent_smb_stream_optional_datetime(digest, value.closed_at)
    _persistent_smb_stream_text(digest, value.src_ip)
    _persistent_smb_stream_int(digest, value.src_port)
    _persistent_smb_stream_text(digest, value.dst_ip)
    _persistent_smb_stream_int(digest, value.dst_port)
    _persistent_smb_stream_text(digest, value.protocol)
    _persistent_smb_stream_text(digest, value.service)
    _persistent_smb_stream_text(digest, value.zeek_uid)
    _persistent_smb_stream_text(digest, value.conn_id)
    _persistent_smb_stream_bool(digest, value.duration is not None)
    if value.duration is not None:
        _persistent_smb_stream_text(digest, value.duration.hex())
    _persistent_smb_stream_text(digest, value.conn_state)
    _persistent_smb_stream_text(digest, value.history)
    _persistent_smb_stream_traffic(digest, value.traffic)
    _persistent_smb_stream_int(digest, value.initiating_pid)
    _persistent_smb_stream_int(digest, value.responding_pid)
    _persistent_smb_stream_bool(digest, value.local_orig)
    _persistent_smb_stream_bool(digest, value.local_resp)
    _persistent_smb_stream_int(digest, value.ip_proto)
    _persistent_smb_stream_bool(digest, value.link_local)
    _persistent_smb_stream_bool(digest, value.application_layer_only)
    return digest.hexdigest()


def _persistent_smb_stream_tuple(
    sink: _PersistentSmbDigestSink,
    value: _PersistentSmbTupleFacts,
) -> None:
    _persistent_smb_stream_text(sink, value.src_ip)
    _persistent_smb_stream_int(sink, value.src_port)
    _persistent_smb_stream_text(sink, value.dst_ip)
    _persistent_smb_stream_int(sink, value.dst_port)
    _persistent_smb_stream_text(sink, value.protocol)


def _persistent_smb_stream_nat(
    sink: _PersistentSmbDigestSink,
    value: _PersistentSmbNatFacts | None,
) -> None:
    _persistent_smb_stream_bool(sink, value is not None)
    if value is None:
        return
    _persistent_smb_stream_text(sink, value.nat_type)
    _persistent_smb_stream_text(sink, value.direction)
    _persistent_smb_stream_text(sink, value.local_ip)
    _persistent_smb_stream_int(sink, value.local_port)
    _persistent_smb_stream_text(sink, value.global_ip)
    _persistent_smb_stream_int(sink, value.global_port)
    _persistent_smb_stream_datetime(sink, value.built_time)
    _persistent_smb_stream_optional_datetime(sink, value.teardown_time)


def _persistent_smb_stream_text_pairs(
    sink: _PersistentSmbDigestSink,
    value: tuple[tuple[str, str], ...],
) -> None:
    _persistent_smb_stream_int(sink, len(value))
    for first, second in value:
        _persistent_smb_stream_text(sink, first)
        _persistent_smb_stream_text(sink, second)


def _persistent_smb_observation_digest(
    value: _PersistentSmbObservationFacts,
    ordinal: int,
    *,
    lossless: bool,
) -> str:
    digest = hashlib.sha256()
    _persistent_smb_stream_field(digest, b"persistent-smb-traffic-observation-v2")
    _persistent_smb_stream_int(digest, ordinal)
    _persistent_smb_stream_bool(digest, lossless)
    _persistent_smb_stream_text(digest, value.sensor_identity)
    _persistent_smb_stream_text(digest, value.path_role)
    _persistent_smb_stream_text(digest, value.capture_profile)
    _persistent_smb_stream_tuple(digest, value.tuple_view)
    _persistent_smb_stream_text(digest, value.connection_uid)
    _persistent_smb_stream_text_pairs(digest, value.connection_ids)
    _persistent_smb_stream_bool(digest, value.local_orig)
    _persistent_smb_stream_bool(digest, value.local_resp)
    _persistent_smb_stream_datetime(digest, value.observed_start_time)
    _persistent_smb_stream_optional_datetime(digest, value.observed_close_time)
    _persistent_smb_stream_traffic(digest, value.traffic)
    _persistent_smb_stream_int(digest, len(value.visible_formats))
    for format_name in value.visible_formats:
        _persistent_smb_stream_text(digest, format_name)
    _persistent_smb_stream_text(digest, value.history)
    _persistent_smb_stream_text(digest, value.firewall_teardown_reason)
    _persistent_smb_stream_optional_datetime(digest, value.firewall_teardown_time)
    _persistent_smb_stream_bool(digest, value.firewall_teardown_observed)
    _persistent_smb_stream_nat(digest, value.nat)
    _persistent_smb_stream_time_pairs(digest, value.source_times)
    _persistent_smb_stream_int(digest, len(value.source_durations))
    for key, duration in value.source_durations:
        _persistent_smb_stream_text(digest, key)
        _persistent_smb_stream_text(digest, duration.hex())
    return digest.hexdigest()


def _persistent_smb_close_facts_digest(
    binding: _PersistentSmbBindingFacts,
    canonical: _PersistentSmbTrafficFacts,
    observations: tuple[_PersistentSmbTrafficFacts, ...],
) -> str:
    """Stream the authenticated opening fingerprint and exact final ledger cohort."""

    digest = hashlib.sha256()
    _persistent_smb_stream_field(digest, b"persistent-smb-traffic-close-facts-v2")
    _persistent_smb_stream_text(digest, binding.authority_id)
    _persistent_smb_stream_text(digest, binding.binding_id)
    _persistent_smb_stream_field(digest, binding.transport_digest.encode("ascii"))
    _persistent_smb_stream_int(digest, len(binding.observation_digests))
    for observation_digest in binding.observation_digests:
        _persistent_smb_stream_field(digest, observation_digest.encode("ascii"))
    _persistent_smb_stream_int(digest, len(binding.lossless_ordinals))
    for ordinal in binding.lossless_ordinals:
        _persistent_smb_stream_int(digest, ordinal)
    _persistent_smb_stream_field(digest, binding.integrity.encode("ascii"))
    _persistent_smb_stream_traffic(digest, canonical)
    _persistent_smb_stream_int(digest, len(observations))
    for ordinal, observation in enumerate(observations):
        _persistent_smb_stream_int(digest, ordinal)
        _persistent_smb_stream_traffic(digest, observation)
    return digest.hexdigest()


def _persistent_smb_traffic_values_equal(
    first: _PersistentSmbTrafficFacts,
    second: _PersistentSmbTrafficFacts,
) -> bool:
    return bool(
        first.orig_payload == second.orig_payload
        and first.orig_packets == second.orig_packets
        and first.orig_ip == second.orig_ip
        and first.resp_payload == second.resp_payload
        and first.resp_packets == second.resp_packets
        and first.resp_ip == second.resp_ip
        and first.missed_orig == second.missed_orig
        and first.missed_resp == second.missed_resp
    )


def _persistent_smb_traffic_monotonic(
    original: _PersistentSmbTrafficFacts,
    final: _PersistentSmbTrafficFacts,
) -> bool:
    return bool(
        final.orig_payload >= original.orig_payload
        and final.orig_packets >= original.orig_packets
        and final.orig_ip >= original.orig_ip
        and final.resp_payload >= original.resp_payload
        and final.resp_packets >= original.resp_packets
        and final.resp_ip >= original.resp_ip
        and final.missed_orig >= original.missed_orig
        and final.missed_resp >= original.missed_resp
    )


def _persistent_smb_validate_capture(
    canonical: _PersistentSmbTrafficFacts,
    observed: _PersistentSmbTrafficFacts,
    label: str,
) -> None:
    for direction, canonical_values, observed_values in (
        (
            "orig",
            (canonical.orig_payload, canonical.orig_packets, canonical.orig_ip),
            (observed.orig_payload, observed.orig_packets, observed.orig_ip),
        ),
        (
            "resp",
            (canonical.resp_payload, canonical.resp_packets, canonical.resp_ip),
            (observed.resp_payload, observed.resp_packets, observed.resp_ip),
        ),
    ):
        if any(
            candidate > source
            for candidate, source in zip(observed_values, canonical_values, strict=True)
        ):
            raise ValueError(f"{label}.{direction} traffic exceeds canonical traffic")
    for direction, canonical_payload, observed_payload, canonical_missed, observed_missed in (
        (
            "orig",
            canonical.orig_payload,
            observed.orig_payload,
            canonical.missed_orig,
            observed.missed_orig,
        ),
        (
            "resp",
            canonical.resp_payload,
            observed.resp_payload,
            canonical.missed_resp,
            observed.missed_resp,
        ),
    ):
        if observed_missed < canonical_missed:
            raise ValueError(f"{label}.{direction} missed bytes understate canonical traffic")
        capture_gap = observed_missed - canonical_missed
        if observed_payload + capture_gap != canonical_payload:
            raise ValueError(f"{label}.{direction} capture accounting is not lossless-plus-gap")
    if observed.missed_orig == canonical.missed_orig and (
        observed.orig_packets != canonical.orig_packets or observed.orig_ip != canonical.orig_ip
    ):
        raise ValueError(f"{label}.orig packet accounting lacks a capture-gap proof")
    if observed.missed_resp == canonical.missed_resp and (
        observed.resp_packets != canonical.resp_packets or observed.resp_ip != canonical.resp_ip
    ):
        raise ValueError(f"{label}.resp packet accounting lacks a capture-gap proof")


def _persistent_smb_history(history: str, traffic: _PersistentSmbTrafficFacts) -> str:
    """Derive the two traffic-gap markers from final bounded traffic facts."""

    base = "".join(character for character in history if character not in "Gg")
    if traffic.missed_orig:
        base += "G"
    if traffic.missed_resp:
        base += "g"
    return base


def _persistent_smb_hex_digest(value: object, label: str) -> str:
    if type(value) is not str or len(value) != 64:
        raise ValueError(f"{label} requires one exact SHA-256 digest")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError(f"{label} requires one exact SHA-256 digest") from error
    if any(byte not in b"0123456789abcdef" for byte in encoded):
        raise ValueError(f"{label} requires one exact SHA-256 digest")
    return value


def _snapshot_persistent_smb_binding(
    value: object,
    budget: _PersistentSmbAggregateBudget | None = None,
) -> _PersistentSmbBindingFacts:
    authority_id, binding_id, transport_digest, observation_digests, ordinals, integrity = (
        _persistent_smb_slots(
            value,
            PersistentSmbTrafficRebindBinding,
            _PERSISTENT_SMB_BINDING_FIELDS,
            "binding",
        )
    )
    if budget is not None:
        budget.consume_work(len(_PERSISTENT_SMB_BINDING_FIELDS))
        budget.consume_text(authority_id, "binding.authority_id")
        budget.consume_text(binding_id, "binding.binding_id")
        budget.consume_text(transport_digest, "binding.transport_digest")
        budget.consume_text(integrity, "binding._integrity")
    checked_authority = _persistent_smb_text(authority_id, "binding.authority_id")
    checked_binding = _persistent_smb_text(binding_id, "binding.binding_id")
    checked_transport = _persistent_smb_hex_digest(
        transport_digest,
        "binding.transport_digest",
    )
    if type(observation_digests) is not tuple or len(observation_digests) > (
        _PERSISTENT_SMB_MAX_OBSERVATIONS
    ):
        raise TypeError("binding.observation_digests requires one bounded exact tuple")
    if budget is not None:
        budget.consume_items(len(observation_digests))
        for digest in observation_digests:
            budget.consume_text(digest, "binding observation digest")
    checked_digests = tuple(
        _persistent_smb_hex_digest(item, "binding observation digest")
        for item in observation_digests
    )
    if type(ordinals) is not tuple or len(ordinals) > _PERSISTENT_SMB_MAX_OBSERVATIONS:
        raise TypeError("binding.lossless_ordinals requires one bounded exact tuple")
    if budget is not None:
        budget.consume_items(len(ordinals))
        budget.consume_work(len(ordinals))
    checked_ordinals = tuple(
        _persistent_smb_int(item, "binding lossless ordinal", maximum=len(checked_digests) - 1)
        for item in ordinals
    )
    if tuple(sorted(set(checked_ordinals))) != checked_ordinals:
        raise ValueError("binding lossless ordinals must be unique and ordered")
    checked_integrity = _persistent_smb_hex_digest(integrity, "binding integrity")
    return _PersistentSmbBindingFacts(
        authority_id=checked_authority,
        binding_id=checked_binding,
        transport_digest=checked_transport,
        observation_digests=checked_digests,
        lossless_ordinals=checked_ordinals,
        integrity=checked_integrity,
    )


def _materialize_persistent_smb_transport(
    facts: _PersistentSmbTransportFacts,
    traffic: NetworkTrafficLedger,
) -> NetworkTransactionPlan:
    return NetworkTransactionPlan(
        stable_id=facts.stable_id,
        hostname=facts.hostname,
        outcome=facts.outcome,
        phase_times=tuple(facts.phase_times),
        started_at=facts.started_at,
        closed_at=facts.closed_at,
        src_ip=facts.src_ip,
        src_port=facts.src_port,
        dst_ip=facts.dst_ip,
        dst_port=facts.dst_port,
        protocol=facts.protocol,
        service=facts.service,
        zeek_uid=facts.zeek_uid,
        conn_id=facts.conn_id,
        duration=facts.duration,
        conn_state=facts.conn_state,
        history=_persistent_smb_history(facts.history, _snapshot_materialized_traffic(traffic)),
        traffic=traffic,
        initiating_pid=facts.initiating_pid,
        responding_pid=facts.responding_pid,
        local_orig=facts.local_orig,
        local_resp=facts.local_resp,
        ip_proto=facts.ip_proto,
        link_local=facts.link_local,
        application_layer_only=facts.application_layer_only,
    )


def _snapshot_materialized_traffic(value: NetworkTrafficLedger) -> _PersistentSmbTrafficFacts:
    """Read a helper-created exact ledger whose constructor already enforced its shape."""

    orig = object.__getattribute__(value, "orig")
    resp = object.__getattribute__(value, "resp")
    return _PersistentSmbTrafficFacts(
        object.__getattribute__(orig, "payload_bytes"),
        object.__getattribute__(orig, "packets"),
        object.__getattribute__(orig, "ip_bytes"),
        object.__getattribute__(resp, "payload_bytes"),
        object.__getattribute__(resp, "packets"),
        object.__getattribute__(resp, "ip_bytes"),
        object.__getattribute__(value, "missed_orig_bytes"),
        object.__getattribute__(value, "missed_resp_bytes"),
    )


def _materialize_persistent_smb_observation(
    facts: _PersistentSmbObservationFacts,
    traffic: NetworkTrafficLedger,
) -> NetworkSensorObservation:
    traffic_facts = _snapshot_materialized_traffic(traffic)
    return NetworkSensorObservation(
        sensor_identity=facts.sensor_identity,
        path_role=facts.path_role,
        capture_profile=facts.capture_profile,
        tuple_view=facts.tuple_view.materialize(),
        connection_uid=facts.connection_uid,
        connection_ids=tuple(facts.connection_ids),
        file_ids=(),
        local_orig=facts.local_orig,
        local_resp=facts.local_resp,
        observed_start_time=facts.observed_start_time,
        observed_close_time=facts.observed_close_time,
        traffic=traffic,
        visible_formats=frozenset(facts.visible_formats),
        history=_persistent_smb_history(facts.history, traffic_facts),
        file_observations=(),
        http_request_body_len=None,
        http_response_body_len=None,
        firewall_teardown_reason=facts.firewall_teardown_reason,
        firewall_teardown_time=facts.firewall_teardown_time,
        firewall_teardown_observed=facts.firewall_teardown_observed,
        nat=None if facts.nat is None else facts.nat.materialize(),
        source_times=tuple(facts.source_times),
        source_durations=tuple(facts.source_durations),
    )


class PersistentSmbTrafficRebindAuthority:
    """Issue and authenticate stateless bounded SMB opening bindings.

    The authority retains only its private signing key and identifier. Bindings
    carry ordered scalar digests, never transport, observation, emitter, timing,
    or callback references. Byte-identical binding copies are harmless. Final
    reconstruction is deliberately private and unavailable without a future
    dispatcher-owned close-proof authenticator.
    """

    __slots__ = ("_authority_id", "_secret")

    def __init__(self) -> None:
        self._authority_id = secrets.token_hex(16)
        self._secret = secrets.token_bytes(32)

    def _integrity(
        self,
        binding_id: str,
        transport_digest: str,
        observation_digests: tuple[str, ...],
        lossless_ordinals: tuple[int, ...],
    ) -> str:
        digest = hmac.new(self._secret, digestmod=hashlib.sha256)
        _persistent_smb_stream_field(digest, b"persistent-smb-traffic-rebind-binding-v2")
        _persistent_smb_stream_text(digest, self._authority_id)
        _persistent_smb_stream_text(digest, binding_id)
        _persistent_smb_stream_field(digest, transport_digest.encode("ascii"))
        _persistent_smb_stream_int(digest, len(observation_digests))
        for observation_digest in observation_digests:
            _persistent_smb_stream_field(digest, observation_digest.encode("ascii"))
        _persistent_smb_stream_int(digest, len(lossless_ordinals))
        for ordinal in lossless_ordinals:
            _persistent_smb_stream_int(digest, ordinal)
        return digest.hexdigest()

    @staticmethod
    def _snapshot_observation_cohort(
        observations: object,
        canonical: _PersistentSmbTransportFacts,
        canonical_traffic_object: NetworkTrafficLedger,
        budget: _PersistentSmbAggregateBudget | None = None,
    ) -> tuple[
        tuple[_PersistentSmbObservationFacts, ...],
        tuple[int, ...],
    ]:
        if type(observations) is not tuple:
            raise TypeError("Persistent SMB observations require an exact tuple")
        if len(observations) > _PERSISTENT_SMB_MAX_OBSERVATIONS:
            raise ValueError("Persistent SMB observations exceed their cohort bound")
        if budget is not None:
            budget.consume_work()
            budget.consume_items(len(observations))
        snapshots: list[_PersistentSmbObservationFacts] = []
        lossless_ordinals: list[int] = []
        sensor_identities: set[str] = set()
        connection_uids: set[str] = set()
        mapped_connection_uids: set[str] = set()
        for ordinal, observation in enumerate(observations):
            snapshot, traffic_object = _snapshot_persistent_smb_observation(
                observation,
                ordinal,
                budget,
            )
            normalized_sensor_identity = snapshot.sensor_identity.casefold()
            if normalized_sensor_identity in sensor_identities:
                raise ValueError("Persistent SMB observations require a unique sensor identity")
            expected_connection_uid = derive_sensor_identifier(
                canonical.zeek_uid,
                snapshot.sensor_identity,
            )
            if snapshot.connection_uid != expected_connection_uid:
                raise ValueError("Persistent SMB observations require the derived connection UID")
            expected_connection_ids = ((canonical.zeek_uid, expected_connection_uid),)
            if snapshot.connection_ids != expected_connection_ids:
                raise ValueError(
                    "Persistent SMB observations require one canonical connection mapping"
                )
            if snapshot.connection_uid in connection_uids:
                raise ValueError("Persistent SMB observations require a unique connection UID")
            mapped_connection_uid = snapshot.connection_ids[0][1]
            if mapped_connection_uid in mapped_connection_uids:
                raise ValueError(
                    "Persistent SMB observations require a unique mapped connection UID"
                )
            sensor_identities.add(normalized_sensor_identity)
            connection_uids.add(snapshot.connection_uid)
            mapped_connection_uids.add(mapped_connection_uid)
            _persistent_smb_validate_capture(
                canonical.traffic,
                snapshot.traffic,
                f"observations[{ordinal}]",
            )
            lossless = _persistent_smb_traffic_values_equal(
                canonical.traffic,
                snapshot.traffic,
            )
            aliases = traffic_object is canonical_traffic_object
            if lossless and not aliases:
                raise ValueError(f"Lossless observation {ordinal} must alias canonical traffic")
            if aliases and not lossless:
                raise ValueError(f"Observation {ordinal} has inconsistent traffic aliasing")
            if lossless:
                lossless_ordinals.append(ordinal)
            snapshots.append(snapshot)
        return tuple(snapshots), tuple(lossless_ordinals)

    def issue_binding(
        self,
        transport: NetworkTransactionPlan,
        observations: tuple[NetworkSensorObservation, ...],
    ) -> PersistentSmbTrafficRebindBinding:
        """Sign one exact SMB transport and its ordered, already-decided sensors."""

        _persistent_smb_schema_preflight()
        _preflight_persistent_smb_opening(transport, observations)
        snapshot_budget = _PersistentSmbAggregateBudget()
        transport_snapshot, transport_traffic_object = _snapshot_persistent_smb_transport(
            transport,
            snapshot_budget,
        )
        snapshots, lossless_ordinals = self._snapshot_observation_cohort(
            observations,
            transport_snapshot,
            transport_traffic_object,
            snapshot_budget,
        )
        transport_digest = _persistent_smb_transport_digest(transport_snapshot)
        lossless_set = frozenset(lossless_ordinals)
        observation_digests = tuple(
            _persistent_smb_observation_digest(
                snapshot,
                ordinal,
                lossless=ordinal in lossless_set,
            )
            for ordinal, snapshot in enumerate(snapshots)
        )
        binding_id = secrets.token_hex(16)
        integrity = self._integrity(
            binding_id,
            transport_digest,
            observation_digests,
            lossless_ordinals,
        )
        return PersistentSmbTrafficRebindBinding(
            authority_id=self._authority_id,
            binding_id=binding_id,
            transport_digest=transport_digest,
            observation_digests=observation_digests,
            lossless_ordinals=lossless_ordinals,
            _integrity=integrity,
        )

    def _prepare_close_proof_digest(
        self,
        binding: PersistentSmbTrafficRebindBinding,
        final_traffic: NetworkTrafficLedger,
        final_observation_traffic: tuple[NetworkTrafficLedger, ...],
    ) -> str:
        """Prepare the bounded final-facts digest an outer proof must authenticate.

        This private helper does not issue or authenticate a close proof. The
        future dispatcher owner calls it only after authenticating State's exact
        terminal result and its own ordered sensor projection.
        """

        _persistent_smb_schema_preflight()
        _preflight_persistent_smb_close_facts(
            binding,
            final_traffic,
            final_observation_traffic,
        )
        snapshot_budget = _PersistentSmbAggregateBudget()
        binding_snapshot = _snapshot_persistent_smb_binding(binding, snapshot_budget)
        expected_integrity = self._integrity(
            binding_snapshot.binding_id,
            binding_snapshot.transport_digest,
            binding_snapshot.observation_digests,
            binding_snapshot.lossless_ordinals,
        )
        if binding_snapshot.authority_id != self._authority_id or not hmac.compare_digest(
            binding_snapshot.integrity,
            expected_integrity,
        ):
            raise ValueError("Persistent SMB traffic binding is foreign or tampered")
        if len(final_observation_traffic) != len(binding_snapshot.observation_digests):
            raise ValueError(
                "Every persistent network observation requires one final traffic ledger"
            )

        final_snapshot, _final_object = _snapshot_persistent_smb_traffic(
            final_traffic,
            "final_traffic",
            snapshot_budget,
        )
        snapshot_budget.consume_work()
        snapshot_budget.consume_items(len(final_observation_traffic))
        lossless_set = frozenset(binding_snapshot.lossless_ordinals)
        final_observation_snapshots: list[_PersistentSmbTrafficFacts] = []
        for ordinal, candidate in enumerate(final_observation_traffic):
            candidate_snapshot, candidate_object = _snapshot_persistent_smb_traffic(
                candidate,
                f"final_observation_traffic[{ordinal}]",
                snapshot_budget,
            )
            _persistent_smb_validate_capture(
                final_snapshot,
                candidate_snapshot,
                f"final_observation_traffic[{ordinal}]",
            )
            final_is_lossless = _persistent_smb_traffic_values_equal(
                final_snapshot,
                candidate_snapshot,
            )
            candidate_aliases = candidate_object is final_traffic
            if ordinal in lossless_set:
                if not final_is_lossless or not candidate_aliases:
                    raise ValueError(
                        f"Lossless observation {ordinal} must alias final canonical traffic"
                    )
            elif final_is_lossless or candidate_aliases:
                raise ValueError(
                    f"Lossy observation {ordinal} cannot change its signed alias topology"
                )
            final_observation_snapshots.append(candidate_snapshot)
        return _persistent_smb_close_facts_digest(
            binding_snapshot,
            final_snapshot,
            tuple(final_observation_snapshots),
        )

    def _rebind_authenticated_close(
        self,
        binding: PersistentSmbTrafficRebindBinding,
        transport: NetworkTransactionPlan,
        final_traffic: NetworkTrafficLedger,
        observations: tuple[NetworkSensorObservation, ...],
        final_observation_traffic: tuple[NetworkTrafficLedger, ...],
        proof: object,
        proof_authenticator: _PersistentSmbTrafficCloseProofAuthenticator,
    ) -> tuple[NetworkTransactionPlan, tuple[NetworkSensorObservation, ...]]:
        """Privately reconstruct one externally authenticated final SMB cohort.

        The method performs no planning, RNG, visibility, timing, or state
        mutation. The future dispatcher must supply an opaque close proof whose
        trusted authenticator cross-binds State's terminal result and the ordered
        sensor projection. No production caller exists in this slice.
        """

        _persistent_smb_schema_preflight()
        _preflight_persistent_smb_close_inputs(
            binding,
            transport,
            final_traffic,
            observations,
            final_observation_traffic,
        )
        snapshot_budget = _PersistentSmbAggregateBudget()
        binding_snapshot = _snapshot_persistent_smb_binding(binding, snapshot_budget)
        transport_snapshot, transport_traffic_object = _snapshot_persistent_smb_transport(
            transport,
            snapshot_budget,
        )
        observation_snapshots, lossless_ordinals = self._snapshot_observation_cohort(
            observations,
            transport_snapshot,
            transport_traffic_object,
            snapshot_budget,
        )
        final_snapshot, _final_object = _snapshot_persistent_smb_traffic(
            final_traffic,
            "final_traffic",
            snapshot_budget,
        )
        if type(final_observation_traffic) is not tuple:
            raise TypeError("Persistent final observation traffic requires an exact tuple")
        if len(final_observation_traffic) != len(observation_snapshots):
            raise ValueError(
                "Every persistent network observation requires one final traffic ledger"
            )
        snapshot_budget.consume_work()
        snapshot_budget.consume_items(len(final_observation_traffic))

        final_candidates: list[tuple[_PersistentSmbTrafficFacts, bool]] = []
        for ordinal, candidate in enumerate(final_observation_traffic):
            candidate_snapshot, candidate_object = _snapshot_persistent_smb_traffic(
                candidate,
                f"final_observation_traffic[{ordinal}]",
                snapshot_budget,
            )
            final_candidates.append((candidate_snapshot, candidate_object is final_traffic))

        # No digest or trusted callback executes until the complete current graph
        # has passed the second cumulative census used by these exact slot locals.
        expected_integrity = self._integrity(
            binding_snapshot.binding_id,
            binding_snapshot.transport_digest,
            binding_snapshot.observation_digests,
            binding_snapshot.lossless_ordinals,
        )
        if binding_snapshot.authority_id != self._authority_id or not hmac.compare_digest(
            binding_snapshot.integrity,
            expected_integrity,
        ):
            raise ValueError("Persistent SMB traffic binding is foreign or tampered")

        transport_digest = _persistent_smb_transport_digest(transport_snapshot)
        if not hmac.compare_digest(transport_digest, binding_snapshot.transport_digest):
            raise ValueError("Persistent SMB transport does not match its signed binding")
        derived_lossless_set = frozenset(lossless_ordinals)
        observation_digests = tuple(
            _persistent_smb_observation_digest(
                observation,
                ordinal,
                lossless=ordinal in derived_lossless_set,
            )
            for ordinal, observation in enumerate(observation_snapshots)
        )
        if lossless_ordinals != binding_snapshot.lossless_ordinals or len(
            observation_digests
        ) != len(binding_snapshot.observation_digests):
            raise ValueError("Persistent SMB observations do not match signed sensor ordinals")
        if any(
            not hmac.compare_digest(actual, expected)
            for actual, expected in zip(
                observation_digests,
                binding_snapshot.observation_digests,
                strict=True,
            )
        ):
            raise ValueError("Persistent SMB observations do not match signed sensor ordinals")
        if not _persistent_smb_traffic_monotonic(transport_snapshot.traffic, final_snapshot):
            raise ValueError("Persistent canonical traffic cannot shrink at close")

        final_observation_snapshots: list[_PersistentSmbTrafficFacts] = []
        lossless_set = frozenset(binding_snapshot.lossless_ordinals)
        for ordinal, (original, final_candidate) in enumerate(
            zip(observation_snapshots, final_candidates, strict=True)
        ):
            candidate_snapshot, candidate_aliases = final_candidate
            if not _persistent_smb_traffic_monotonic(original.traffic, candidate_snapshot):
                raise ValueError(f"Persistent observation {ordinal} traffic cannot shrink at close")
            _persistent_smb_validate_capture(
                final_snapshot,
                candidate_snapshot,
                f"final_observation_traffic[{ordinal}]",
            )
            final_is_lossless = _persistent_smb_traffic_values_equal(
                final_snapshot,
                candidate_snapshot,
            )
            if ordinal in lossless_set:
                if not final_is_lossless or not candidate_aliases:
                    raise ValueError(
                        f"Lossless observation {ordinal} must alias final canonical traffic"
                    )
            elif final_is_lossless or candidate_aliases:
                raise ValueError(
                    f"Lossy observation {ordinal} cannot change its signed alias topology"
                )
            final_observation_snapshots.append(candidate_snapshot)

        close_facts_digest = _persistent_smb_close_facts_digest(
            binding_snapshot,
            final_snapshot,
            tuple(final_observation_snapshots),
        )
        authenticated = proof_authenticator.authenticates_persistent_smb_close_proof(
            proof,
            binding_snapshot.binding_id,
            close_facts_digest,
        )
        if type(authenticated) is not bool or not authenticated:
            raise ValueError("Persistent SMB close proof does not authenticate final traffic")

        rebound_traffic = final_snapshot.materialize()
        rebound_transport = _materialize_persistent_smb_transport(
            transport_snapshot,
            rebound_traffic,
        )
        rebound_observations: list[NetworkSensorObservation] = []
        for ordinal, (observation, traffic_snapshot) in enumerate(
            zip(observation_snapshots, final_observation_snapshots, strict=True)
        ):
            rebound_observation_traffic = (
                rebound_traffic if ordinal in lossless_set else traffic_snapshot.materialize()
            )
            rebound_observations.append(
                _materialize_persistent_smb_observation(
                    observation,
                    rebound_observation_traffic,
                )
            )
        return rebound_transport, tuple(rebound_observations)


class NetworkObservationPlanner:
    """Project canonical network truth through configured sensor behavior."""

    def __init__(
        self,
        visibility_engine: NetworkVisibilityEngine | None,
        output_end_time: datetime | None = None,
        timing_runtime: TimingRuntime | None = None,
    ) -> None:
        self.visibility_engine = visibility_engine
        self.output_end_time = output_end_time
        self._runtime_injected = timing_runtime is not None
        self.timing_runtime = timing_runtime or TimingRuntime.compatibility_default()

    def plan(
        self,
        event: CanonicalOccurrence,
        visible_formats: set[str],
        *,
        sensor_formats: Mapping[str, Collection[str]] | None = None,
    ) -> tuple[NetworkSensorObservation, ...]:
        """Return deterministic observations for every visible network sensor."""

        network = event.network
        if network is None:
            return ()
        transaction = network
        planned_sensor_formats = (
            {
                sensor_identity: set(formats) & visible_formats
                for sensor_identity, formats in sensor_formats.items()
                if set(formats) & visible_formats
            }
            if sensor_formats is not None
            else self._sensor_formats(event, visible_formats)
        )
        canonical_file_ids = self._canonical_file_ids(event)
        canonical_connection_ids = self._canonical_connection_ids(event)
        runtime = self._runtime_for_event(transaction.started_at)
        observations: list[NetworkSensorObservation] = []
        for sensor_identity, formats in sorted(planned_sensor_formats.items()):
            sensor = (
                self.visibility_engine.get_sensor(sensor_identity)
                if self.visibility_engine is not None
                else None
            )
            requested_profile = sensor.capture_profile if sensor is not None else ""
            timing = network_sensor_observation_timing(requested_profile or None)
            path_role = (
                self.visibility_engine.infer_sensor_path_role(
                    sensor_identity,
                    transaction.src_ip,
                    transaction.dst_ip,
                    link_local=network.link_local,
                )
                if self.visibility_engine is not None
                else "unspecified"
            )
            tuple_view, local_orig, local_resp = self._sensor_view(event, sensor)
            observed_start, observed_close = self._observed_interval(
                transaction.started_at,
                transaction.closed_at,
                timing,
                sensor_identity,
                path_role,
                transaction.conn_id or transaction.zeek_uid or transaction.stable_id,
                runtime,
            )
            observation_scope = TimingScope(
                stable_id=transaction.stable_id or transaction.zeek_uid,
                source=sensor_identity.casefold(),
                lifecycle_id=path_role,
            )
            firewall_reason, firewall_teardown = self._firewall_teardown_plan(
                event,
                formats,
                sensor_identity,
                observed_start,
                observed_close,
                scope=observation_scope,
                runtime=runtime,
            )
            firewall_teardown_observed = self._before_output_end(firewall_teardown)
            observed_traffic = self._observed_traffic(
                transaction.traffic,
                timing,
                sensor_identity,
                transaction.stable_id,
                transaction.protocol,
            )
            history, file_observations, request_body_len, response_body_len = (
                self._observed_protocol(event, observed_traffic)
            )
            source_times, source_durations = self._source_native_protocol_timing(
                event,
                canonical_start=ensure_utc(transaction.started_at),
                observed_start=observed_start,
                observed_close=observed_close,
                sensor_identity=sensor_identity,
                path_role=path_role,
                visible_formats=formats,
                timing=timing,
                runtime=runtime,
            )
            admitted_formats = self._admitted_source_formats(
                formats,
                source_times=source_times,
                observed_start=observed_start,
            )
            observations.append(
                NetworkSensorObservation(
                    sensor_identity=sensor_identity,
                    path_role=path_role,
                    capture_profile=timing.profile_name,
                    tuple_view=tuple_view,
                    connection_uid=derive_sensor_identifier(
                        transaction.zeek_uid,
                        sensor_identity,
                    ),
                    connection_ids=tuple(
                        (connection_id, derive_sensor_identifier(connection_id, sensor_identity))
                        for connection_id in canonical_connection_ids
                    ),
                    file_ids=tuple(
                        (file_id, derive_sensor_identifier(file_id, sensor_identity))
                        for file_id in canonical_file_ids
                    ),
                    local_orig=local_orig,
                    local_resp=local_resp,
                    observed_start_time=observed_start,
                    observed_close_time=observed_close,
                    traffic=observed_traffic,
                    visible_formats=frozenset(admitted_formats),
                    history=history,
                    file_observations=file_observations,
                    http_request_body_len=request_body_len,
                    http_response_body_len=response_body_len,
                    firewall_teardown_reason=firewall_reason,
                    firewall_teardown_time=firewall_teardown,
                    firewall_teardown_observed=firewall_teardown_observed,
                    nat=self._nat_observation(
                        event,
                        observed_start,
                        observed_close,
                        firewall_teardown,
                    ),
                    source_times=source_times,
                    source_durations=source_durations,
                )
            )
        return tuple(observations)

    def _admitted_source_formats(
        self,
        formats: set[str],
        *,
        source_times: tuple[tuple[str, datetime], ...],
        observed_start: datetime,
    ) -> set[str]:
        """Apply the half-open output window to every frozen row in a format."""

        if self.output_end_time is None:
            return set(formats)
        admitted: set[str] = set()
        for format_name in formats:
            prefix = f"{format_name}:"
            row_times = [
                timestamp
                for key, timestamp in source_times
                if key == format_name or key.startswith(prefix)
            ]
            final_time = max(row_times) if row_times else observed_start
            if self._before_output_end(final_time):
                admitted.add(format_name)
        return admitted

    def _before_output_end(self, timestamp: datetime | None) -> bool:
        """Return whether a source-local fan-out row is inside the export window."""

        if timestamp is None or self.output_end_time is None:
            return True
        candidate = timestamp
        gate = self.output_end_time
        if candidate.tzinfo is not None and gate.tzinfo is None:
            candidate = candidate.replace(tzinfo=None)
        elif candidate.tzinfo is None and gate.tzinfo is not None:
            gate = gate.replace(tzinfo=None)
        return candidate < gate

    @classmethod
    def _observed_protocol(
        cls,
        event: CanonicalOccurrence,
        traffic: NetworkTrafficLedger,
    ) -> tuple[str, tuple[FileSensorObservation, ...], int | None, int | None]:
        """Freeze application completeness implied by one sensor's traffic ledger."""

        network = event.network
        if network is None:
            return "", (), None, None

        history = network.history
        if network.protocol.lower() == "tcp":
            if traffic.missed_orig_bytes > 0 and "G" not in history:
                history += "G"
            if traffic.missed_resp_bytes > 0 and "g" not in history:
                history += "g"

        orig_ratio = cls._payload_observation_ratio(
            network.traffic.orig.payload_bytes,
            traffic.orig.payload_bytes,
        )
        resp_ratio = cls._payload_observation_ratio(
            network.traffic.resp.payload_bytes,
            traffic.resp.payload_bytes,
        )
        files: list[FileSensorObservation] = []
        for transfer in event.protocol.file_transfers:
            ratio = orig_ratio if transfer.is_orig else resp_ratio
            total = transfer.total_bytes
            if (
                transfer.entity_body_len is not None
                and transfer.wire_offset is not None
                and transfer.wire_length is not None
            ):
                seen, missing = cls._observed_multipart_leaf(
                    event,
                    transfer,
                    ratio,
                )
            else:
                accounted_total = (
                    total if total is not None else transfer.seen_bytes + transfer.missing_bytes
                )
                seen = min(transfer.seen_bytes, int(transfer.seen_bytes * ratio))
                missing = max(transfer.missing_bytes, accounted_total - seen)
            files.append(
                FileSensorObservation(
                    canonical_id=transfer.fuid,
                    seen_bytes=seen,
                    total_bytes=total,
                    missing_bytes=missing,
                    analyzers_visible=missing == 0 and not transfer.timedout,
                )
            )

        for certificate in event.protocol.x509_chain:
            total = certificate_file_size(certificate)
            seen = int(total * resp_ratio)
            files.append(
                FileSensorObservation(
                    canonical_id=certificate.fuid,
                    seen_bytes=seen,
                    total_bytes=total,
                    missing_bytes=total - seen,
                    analyzers_visible=seen == total,
                )
            )

        request_body_len = None
        response_body_len = None
        http = event.protocol.http
        if http is not None:
            canonical_request = max(
                0,
                http.flow_request_body_len
                if http.flow_request_body_len is not None
                else http.request_body_len,
            )
            canonical_response = max(
                0,
                http.flow_response_body_len
                if http.flow_response_body_len is not None
                else http.response_body_len,
            )
            request_body_len = min(http.request_body_len, int(canonical_request * orig_ratio))
            response_body_len = min(http.response_body_len, int(canonical_response * resp_ratio))

        return history, tuple(files), request_body_len, response_body_len

    @staticmethod
    def _observed_multipart_leaf(
        event: CanonicalOccurrence,
        transfer: object,
        ratio: float,
    ) -> tuple[int, int]:
        """Allocate one stable directional capture gap across multipart wire spans."""

        entity_len = max(0, int(getattr(transfer, "entity_body_len", 0) or 0))
        wire_offset = max(0, int(getattr(transfer, "wire_offset", 0) or 0))
        wire_length = max(0, int(getattr(transfer, "wire_length", 0) or 0))
        decoded_size = max(0, int(getattr(transfer, "seen_bytes", 0) or 0))
        canonical_missing = max(0, int(getattr(transfer, "missing_bytes", 0) or 0))
        if entity_len <= 0 or wire_length <= 0 or ratio >= 1.0:
            return decoded_size, canonical_missing

        missing_wire = min(entity_len, entity_len - int(entity_len * ratio))
        if missing_wire <= 0:
            return decoded_size, canonical_missing
        available_starts = entity_len - missing_wire + 1
        network = event.network
        gap_start = (
            _stable_seed(
                "http-multipart-observation-gap:"
                f"{getattr(network, 'zeek_uid', '')}:"
                f"{getattr(transfer, 'is_orig', False)}:{entity_len}"
            )
            % available_starts
        )
        gap_end = gap_start + missing_wire
        leaf_end = wire_offset + wire_length
        overlap = max(0, min(gap_end, leaf_end) - max(gap_start, wire_offset))
        if overlap <= 0:
            return decoded_size, canonical_missing
        decoded_missing = min(
            decoded_size,
            (decoded_size * overlap + wire_length - 1) // wire_length,
        )
        missing = max(canonical_missing, decoded_missing)
        return max(0, decoded_size - missing), missing

    @staticmethod
    def _payload_observation_ratio(canonical_bytes: int, observed_bytes: int) -> float:
        """Return the bounded fraction of canonical payload visible at one sensor."""

        if canonical_bytes <= 0:
            return 1.0
        return min(1.0, max(0.0, observed_bytes / canonical_bytes))

    @staticmethod
    def _nat_observation(
        event: CanonicalOccurrence,
        observed_start: datetime,
        observed_close: datetime | None,
        firewall_teardown: datetime | None,
    ) -> NatSensorObservation | None:
        """Freeze local/global address roles and translation lifetime for one sensor."""

        nat = event.nat
        network = event.network
        if nat is None or network is None:
            return None
        transaction = network
        teardown_time = None
        if nat.nat_type == "dynamic_pat":
            teardown_time = firewall_teardown or observed_close
        if nat.mapped_src_ip != transaction.src_ip or nat.mapped_src_port != transaction.src_port:
            return NatSensorObservation(
                nat_type=nat.nat_type,
                direction="source",
                local_ip=transaction.src_ip,
                local_port=transaction.src_port,
                global_ip=nat.mapped_src_ip,
                global_port=nat.mapped_src_port,
                built_time=observed_start,
                teardown_time=teardown_time,
            )
        public_dst_ip = nat.pre_nat_dst_ip or transaction.dst_ip
        public_dst_port = nat.pre_nat_dst_port or transaction.dst_port
        if nat.mapped_dst_ip != public_dst_ip or nat.mapped_dst_port != public_dst_port:
            return NatSensorObservation(
                nat_type=nat.nat_type,
                direction="destination",
                local_ip=nat.mapped_dst_ip,
                local_port=nat.mapped_dst_port,
                global_ip=public_dst_ip,
                global_port=public_dst_port,
                built_time=observed_start,
                teardown_time=teardown_time,
            )
        if nat.pre_nat_dst_ip:
            return NatSensorObservation(
                nat_type=nat.nat_type,
                direction="destination",
                local_ip=transaction.dst_ip,
                local_port=transaction.dst_port,
                global_ip=nat.pre_nat_dst_ip,
                global_port=public_dst_port,
                built_time=observed_start,
                teardown_time=teardown_time,
            )
        return None

    @classmethod
    def _firewall_teardown_plan(
        cls,
        event: CanonicalOccurrence,
        formats: set[str],
        sensor_identity: str,
        observed_start: datetime,
        observed_close: datetime | None,
        *,
        scope: TimingScope,
        runtime: TimingRuntime | SourceTimingPlanningRuntime,
    ) -> tuple[str, datetime | None]:
        """Plan source-native ASA teardown time from canonical state and policy."""

        if "cisco_asa" not in formats:
            return "", None
        network = event.network
        if network is None:
            return "", None
        if network.protocol != "tcp":
            anchor = observed_close or observed_start
            return (
                "",
                runtime.sampler.after(
                    anchor,
                    cls._right_skew_distribution(83, 8_500),
                    relationship_key="source.firewall.datagram_teardown",
                    scope=scope,
                    sample_key="datagram",
                ),
            )
        timing: FirewallObservationTiming = firewall_observation_timing(sensor_identity)
        state = network.conn_state
        traffic = network.traffic
        payload_bytes = traffic.orig.payload_bytes + traffic.resp.payload_bytes
        if state in {"S0", "S1", "SH", "SHR"} and payload_bytes == 0:
            timeout_anchor = observed_start + timedelta(
                seconds=timing.tcp_embryonic_timeout_seconds
            )
            return (
                "SYN Timeout",
                runtime.sampler.after(
                    timeout_anchor,
                    cls._right_skew_distribution(137, 18_500),
                    relationship_key="source.firewall.syn_timeout_processing",
                    scope=scope,
                    sample_key="syn-timeout",
                ),
            )
        reason = {
            "REJ": "TCP Reset-O",
            "RSTO": "TCP Reset-O",
            "RSTR": "TCP Reset-I",
            "OTH": "TCP Reset-O",
        }.get(state, "TCP FINs")
        if observed_close is not None:
            anchor = observed_close
            minimum_us, maximum_us = (91, 12_500)
        else:
            anchor = observed_start
            minimum_us, maximum_us = (1_500, 280_000)
        return (
            reason,
            runtime.sampler.after(
                anchor,
                cls._right_skew_distribution(minimum_us, maximum_us),
                relationship_key="source.firewall.connection_teardown",
                scope=scope,
                sample_key=f"teardown:{state or 'unknown'}",
            ),
        )

    @staticmethod
    def _sensor_formats(
        event: CanonicalOccurrence,
        visible_formats: set[str],
    ) -> dict[str, set[str]]:
        sensor_formats: dict[str, set[str]] = {}
        for format_name, sensor_identities in event._sensor_hostnames_by_format.items():
            if format_name not in visible_formats:
                continue
            for sensor_identity in sensor_identities:
                sensor_formats.setdefault(sensor_identity, set()).add(format_name)
        return sensor_formats

    def _sensor_view(
        self,
        event: CanonicalOccurrence,
        sensor: NetworkSensor | None,
    ) -> tuple[NetworkTuple, bool, bool]:
        """Derive one sensor's tuple and locality directly from topology and NAT truth."""

        network = event.network
        transaction = network
        tuple_view = NetworkTuple(
            src_ip=network.src_ip,
            src_port=network.src_port,
            dst_ip=network.dst_ip,
            dst_port=network.dst_port,
            protocol=network.protocol,
        )
        local_orig = network.local_orig
        local_resp = network.local_resp
        nat = event.nat
        if (
            nat is None
            or sensor is None
            or sensor.type == "firewall"
            or self.visibility_engine is None
        ):
            return tuple_view, local_orig, local_resp

        sensor_segments = set(sensor.monitoring_segments)
        inbound = nat.nat_type == "static" and bool(
            nat.pre_nat_dst_ip or (nat.mapped_dst_ip and nat.mapped_dst_ip != transaction.dst_ip)
        )
        if inbound:
            local_dst_ip = nat.mapped_dst_ip or transaction.dst_ip
            local_dst_port = nat.mapped_dst_port or transaction.dst_port
            global_dst_ip = nat.pre_nat_dst_ip or transaction.dst_ip
            global_dst_port = nat.pre_nat_dst_port or transaction.dst_port
            local_segments = self.visibility_engine._resolve_ip_segments(local_dst_ip)
            inside = bool(sensor_segments & local_segments)
            tuple_view = NetworkTuple(
                src_ip=transaction.src_ip,
                src_port=transaction.src_port,
                dst_ip=local_dst_ip if inside else global_dst_ip,
                dst_port=local_dst_port if inside else global_dst_port,
                protocol=transaction.protocol,
            )
            return tuple_view, local_orig, local_resp or inside

        source_segments = self.visibility_engine._resolve_ip_segments(transaction.src_ip)
        if sensor_segments & source_segments:
            return tuple_view, local_orig, local_resp
        tuple_view = NetworkTuple(
            src_ip=nat.mapped_src_ip or transaction.src_ip,
            src_port=nat.mapped_src_port or transaction.src_port,
            dst_ip=nat.mapped_dst_ip or transaction.dst_ip,
            dst_port=nat.mapped_dst_port or transaction.dst_port,
            protocol=transaction.protocol,
        )
        return tuple_view, local_orig, local_resp

    @staticmethod
    def _canonical_file_ids(event: CanonicalOccurrence) -> tuple[str, ...]:
        values: list[str] = []

        def add(candidate: object) -> None:
            if isinstance(candidate, str) and candidate and candidate not in values:
                values.append(candidate)

        if event.protocol.primary_file_transfer is not None:
            add(event.protocol.primary_file_transfer.fuid)
        for transfer in event.protocol.file_transfers:
            add(transfer.fuid)
        if event.protocol.ssl is not None:
            for value in event.protocol.ssl.cert_chain_fuids:
                add(value)
        if event.protocol.http is not None:
            for value in event.protocol.http.orig_fuids:
                add(value)
            for value in event.protocol.http.resp_fuids:
                add(value)
        if event.smtp is not None:
            for value in event.smtp.fuids:
                add(value)
        if event.protocol.leaf_certificate is not None:
            add(event.protocol.leaf_certificate.fuid)
        for certificate in event.protocol.x509_chain:
            add(certificate.fuid)
        if event.protocol.ocsp is not None:
            add(event.protocol.ocsp.id)
        for pe in event.protocol.pe_analyses:
            add(pe.id)
        return tuple(values)

    @staticmethod
    def _canonical_connection_ids(event: CanonicalOccurrence) -> tuple[str, ...]:
        values = [event.network.zeek_uid]
        if event.dhcp is not None:
            values.extend(uid for uid in event.dhcp.uids if uid and uid not in values)
        return tuple(values)

    def _runtime_for_event(
        self,
        canonical_time: datetime,
    ) -> TimingRuntime | SourceTimingPlanningRuntime:
        """Return the injected runtime or a deterministic direct-caller adapter."""

        if self._runtime_injected:
            return active_source_timing_planning_runtime(self.timing_runtime) or self.timing_runtime
        # Low-level callers historically constructed this planner directly. A
        # day-local adapter avoids applying decades of compatibility-epoch drift
        # while production always uses the engine-owned scenario runtime.
        reference = ensure_utc(canonical_time).replace(hour=0, minute=0, second=0, microsecond=0)
        return TimingRuntime(reference_time=reference)

    @classmethod
    def _observed_interval(
        cls,
        canonical_start: datetime,
        canonical_close: datetime | None,
        timing: NetworkSensorObservationTiming,
        sensor_identity: str,
        path_role: str,
        transaction_id: str,
        runtime: TimingRuntime | SourceTimingPlanningRuntime,
    ) -> tuple[datetime, datetime | None]:
        """Project one canonical interval through a physical sensor clock and route."""

        clock_key = cls._sensor_clock_key(sensor_identity, timing.profile_name)
        clock_spec = cls._sensor_clock_spec(timing)
        scope = TimingScope(
            stable_id=transaction_id,
            source=sensor_identity.casefold(),
            lifecycle_id=path_role,
        )
        route_delay = runtime.sampler.sample_timedelta(
            cls._right_skew_distribution(
                timing.route_delay_min_us,
                timing.route_delay_max_us,
            ),
            relationship_key="network.sensor.route_delay",
            scope=scope,
            sample_key="route",
        )
        observed_start = (
            runtime.clocks.project(
                ensure_utc(canonical_start),
                key=clock_key,
                spec=clock_spec,
            )
            + route_delay
        )
        if canonical_close is None:
            return observed_start, None
        observed_close = (
            runtime.clocks.project(
                ensure_utc(canonical_close),
                key=clock_key,
                spec=clock_spec,
            )
            + route_delay
        )
        observed_close += runtime.sampler.sample_timedelta(
            cls._right_skew_distribution(73, 1_800),
            relationship_key="network.sensor.close_processing",
            scope=scope,
            sample_key="close",
        )
        if observed_close < observed_start:
            runtime.audit.record_saturation("network.sensor.clock_interval")
            raise TimingDistributionError(
                "sensor clock projection inverted a canonical network interval: "
                f"sensor={sensor_identity!r} transaction={transaction_id!r}"
            )
        return observed_start, observed_close

    @staticmethod
    def _sensor_clock_key(sensor_identity: str, profile_name: str) -> SourceClockKey:
        return SourceClockKey(
            kind="network_sensor",
            identity=sensor_identity.casefold(),
            profile=profile_name,
        )

    @classmethod
    def _sensor_clock_spec(
        cls,
        timing: NetworkSensorObservationTiming,
    ) -> SourceClockSpec:
        return SourceClockSpec(
            offset_microseconds=cls._clock_distribution(
                timing.clock_offset_min_us,
                timing.clock_offset_max_us,
            ),
            drift_ppm=cls._clock_distribution(
                timing.clock_drift_min_ppm,
                timing.clock_drift_max_ppm,
            ),
            wander=ClockWanderSpec(
                knot_distribution_microseconds=cls._clock_distribution(
                    timing.event_jitter_min_us,
                    timing.event_jitter_max_us,
                ),
                knot_interval=timedelta(minutes=5),
            ),
        )

    @staticmethod
    def _clock_distribution(
        minimum: int, maximum: int
    ) -> ConstantDistribution | TriangularDistribution:
        if maximum <= minimum:
            return ConstantDistribution(float(minimum))
        mode = min(float(maximum), max(float(minimum), 0.0))
        return TriangularDistribution(float(minimum), mode, float(maximum))

    @staticmethod
    def _right_skew_distribution(
        minimum_us: int,
        maximum_us: int,
    ) -> ConstantDistribution | TruncatedLognormalDistribution:
        if maximum_us <= minimum_us + 2:
            return ConstantDistribution(float(max(minimum_us, maximum_us)))
        span = maximum_us - minimum_us
        median = max(1.0, minimum_us + span * 0.18)
        return TruncatedLognormalDistribution(
            median=median,
            sigma=0.78,
            minimum=float(minimum_us),
            maximum=float(maximum_us),
        )

    @classmethod
    def _source_native_protocol_timing(
        cls,
        event: CanonicalOccurrence,
        *,
        canonical_start: datetime,
        observed_start: datetime,
        observed_close: datetime | None,
        sensor_identity: str,
        path_role: str,
        visible_formats: set[str],
        timing: NetworkSensorObservationTiming,
        runtime: TimingRuntime | SourceTimingPlanningRuntime,
    ) -> tuple[tuple[tuple[str, datetime], ...], tuple[tuple[str, float], ...]]:
        """Freeze Zeek connection, analyzer, and file timing before rendering."""

        network = event.network
        if network is None:
            return (), ()
        source_times: dict[str, datetime] = {}
        source_durations: dict[str, float] = {}
        scope = TimingScope(
            stable_id=network.stable_id or network.zeek_uid,
            source=sensor_identity.casefold(),
            lifecycle_id=path_role,
        )
        if "zeek_conn" in visible_formats:
            conn_key = network_source_timing_key("zeek_conn")
            source_times[conn_key] = observed_start
            if observed_close is not None:
                source_durations[conn_key] = (observed_close - observed_start).total_seconds()

        relative_phase_time = observed_start + (ensure_utc(event.timestamp) - canonical_start)
        relative_phase_time = max(observed_start, relative_phase_time)
        if observed_close is not None:
            relative_phase_time = min(relative_phase_time, observed_close)
        for format_name in ("zeek_smb_files", "zeek_smb_mapping", "zeek_weird"):
            if format_name in visible_formats:
                source_times[network_source_timing_key(format_name)] = relative_phase_time

        dns = event.dns
        if dns is not None and "zeek_dns" in visible_formats:
            dns_key = network_source_timing_key("zeek_dns")
            source_rtt_us = max(0, round(float(dns.rtt or 0.0) * 1_000_000))
            dns_upper = observed_close
            if observed_close is not None and source_rtt_us > 0:
                observed_duration_us = round(
                    (observed_close - observed_start).total_seconds() * 1_000_000
                )
                if observed_duration_us <= 8:
                    runtime.audit.record_saturation("source.zeek_dns.admissible_window")
                    raise TimingDistributionError(
                        "source.zeek_dns has no microsecond interior inside its transport"
                    )
                query_reserve_us = (
                    min(
                        observed_duration_us - 4,
                        max(1_004, min(10_000, observed_duration_us // 8)),
                    )
                    if observed_duration_us > 1_008
                    else max(4, observed_duration_us // 3)
                )
                maximum_rtt_us = observed_duration_us - query_reserve_us - 1
                if source_rtt_us > maximum_rtt_us:
                    minimum_rtt_us = max(0, min(maximum_rtt_us - 2, round(maximum_rtt_us * 0.72)))
                    source_rtt_us = runtime.sampler.sample_microseconds(
                        cls._right_skew_distribution(minimum_rtt_us, maximum_rtt_us + 1),
                        relationship_key="source.zeek_dns.rtt_projection",
                        scope=scope,
                        sample_key=f"rtt:{observed_duration_us}",
                    )
                dns_upper = observed_close - timedelta(microseconds=source_rtt_us + 1)
            dns_window = get_timing_window(
                "source.zeek_dns_query",
                default_min_ms=1,
                default_max_ms=95,
                default_position="after",
                default_class="same_observation",
            )
            dns_time = cls._sample_after_within(
                observed_start,
                dns_upper,
                minimum_us=dns_window.min_ms * 1_000,
                maximum_us=dns_window.max_ms * 1_000,
                relationship_key="source.zeek_dns_query",
                scope=scope,
                sample_key=f"dns:{dns.trans_id}:{dns.query}",
                runtime=runtime,
            )
            source_times[dns_key] = dns_time
            if source_rtt_us > 0:
                response_time = dns_time + timedelta(microseconds=source_rtt_us)
                source_times[network_source_timing_key("zeek_dns", "response")] = response_time
                source_durations[dns_key] = source_rtt_us / 1_000_000

        if event.dhcp is not None and "zeek_dhcp" in visible_formats:
            dhcp_key = network_source_timing_key("zeek_dhcp")
            source_times[dhcp_key] = observed_start
            if observed_close is not None:
                dhcp_duration = (observed_close - observed_start).total_seconds()
                source_times[network_source_timing_key("zeek_dhcp", "close")] = observed_close
                source_durations[dhcp_key] = dhcp_duration

        if event.smtp is not None and "zeek_smtp" in visible_formats:
            smtp_key = network_source_timing_key("zeek_smtp")
            source_times[smtp_key] = cls._sample_after_within(
                observed_start,
                observed_close,
                minimum_us=1_300,
                maximum_us=180_000,
                relationship_key="source.zeek_smtp_transaction",
                scope=scope,
                sample_key=f"smtp:{event.smtp.trans_depth}:{event.smtp.msg_id}",
                runtime=runtime,
            )

        if event.ntp is not None and "zeek_ntp" in visible_formats:
            ntp_key = network_source_timing_key("zeek_ntp")
            ntp_time = cls._sample_after_within(
                observed_start,
                observed_close,
                minimum_us=100,
                maximum_us=120_000,
                relationship_key="source.zeek_ntp_response",
                scope=scope,
                sample_key=f"ntp:{event.ntp.stratum}:{event.ntp.xmt_ts}",
                runtime=runtime,
            )
            source_times[ntp_key] = ntp_time

        ssl_time: datetime | None = None
        needs_tls_timing = bool(
            event.protocol.ssl is not None
            or event.protocol.x509_chain
            or event.protocol.leaf_certificate is not None
        )
        if needs_tls_timing:
            ssl_window = get_timing_window(
                "source.zeek_ssl_analyzer",
                default_min_ms=3,
                default_max_ms=650,
                default_position="after",
                default_class="same_observation",
            )
            ssl_time = cls._sample_after_within(
                observed_start,
                observed_close,
                minimum_us=ssl_window.min_ms * 1_000,
                maximum_us=ssl_window.max_ms * 1_000,
                relationship_key="source.zeek_ssl_analyzer",
                scope=scope,
                sample_key="ssl",
                runtime=runtime,
            )
            if "zeek_ssl" in visible_formats and event.protocol.ssl is not None:
                source_times[network_source_timing_key("zeek_ssl")] = ssl_time

        file_window = get_timing_window(
            "source.zeek_file_analyzer",
            default_min_ms=25,
            default_max_ms=250,
            default_position="after",
            default_class="same_observation",
        )
        ocsp = event.protocol.ocsp
        ocsp_transfer = (
            next(
                (
                    transfer
                    for transfer in event.protocol.file_transfers
                    if ocsp is not None and transfer.fuid == ocsp.id
                ),
                None,
            )
            if ocsp is not None
            else None
        )
        ocsp_duration_floor_us = (
            max(4, round(max(0.0, ocsp_transfer.duration) * 0.55 * 1_000_000))
            if ocsp_transfer is not None
            else 0
        )
        http_time: datetime | None = None
        http = event.protocol.http
        if http is not None:
            canonical_request = http.canonical_request_time
            request_anchor = (
                max(observed_start, ssl_time) if ssl_time is not None else observed_start
            )
            if canonical_request is not None:
                request_anchor = max(
                    request_anchor,
                    cls._project_phase_time(
                        ensure_utc(canonical_request),
                        canonical_start=canonical_start,
                        observed_start=observed_start,
                        sensor_identity=sensor_identity,
                        timing=timing,
                        runtime=runtime,
                    ),
                )
            http_window = get_timing_window(
                "source.zeek_http_request",
                default_min_ms=1,
                default_max_ms=450,
                default_position="after",
                default_class="same_observation",
            )
            http_upper = observed_close
            if observed_close is not None and ocsp_duration_floor_us:
                downstream_reserve_us = file_window.min_ms * 1_000 + ocsp_duration_floor_us + 3
                http_upper = observed_close - timedelta(microseconds=downstream_reserve_us)
            http_time = cls._sample_after_within(
                request_anchor,
                http_upper,
                minimum_us=http_window.min_ms * 1_000,
                maximum_us=http_window.max_ms * 1_000,
                relationship_key="source.zeek_http_request",
                scope=scope,
                sample_key=f"http:{http.trans_depth}",
                runtime=runtime,
            )
            if "zeek_http" in visible_formats:
                source_times[network_source_timing_key("zeek_http")] = http_time

        file_times: dict[str, datetime] = {}
        file_durations: dict[str, float] = {}
        previous_file_time: datetime | None = None
        transfers = sorted(event.protocol.file_transfers, key=lambda transfer: not transfer.is_orig)
        for ordinal, transfer in enumerate(transfers):
            anchor = observed_start
            if http_time is not None and transfer.fuid in (*http.orig_fuids, *http.resp_fuids):
                anchor = http_time
            elif ssl_time is not None and transfer.source.upper() == "SSL":
                anchor = ssl_time
            elif transfer.source.upper() == "SMB":
                anchor = relative_phase_time
            if transfer.observation_not_before is not None:
                projected_not_before = cls._project_phase_time(
                    ensure_utc(transfer.observation_not_before),
                    canonical_start=canonical_start,
                    observed_start=observed_start,
                    sensor_identity=sensor_identity,
                    timing=timing,
                    runtime=runtime,
                )
                if observed_close is None or projected_not_before < observed_close:
                    anchor = max(anchor, projected_not_before)
                else:
                    runtime.audit.record_saturation(
                        "source.zeek_file.observation_not_before_window"
                    )
            file_upper = observed_close
            if (
                observed_close is not None
                and ocsp is not None
                and transfer.fuid == ocsp.id
                and ocsp_duration_floor_us
            ):
                file_upper = observed_close - timedelta(microseconds=ocsp_duration_floor_us)
            if previous_file_time is not None:
                anchor = cls._sample_after_within(
                    max(anchor, previous_file_time),
                    file_upper,
                    minimum_us=113,
                    maximum_us=8_500,
                    relationship_key="source.zeek_file.inter_row_gap",
                    scope=scope,
                    sample_key=f"file-gap:{ordinal}:{transfer.fuid}",
                    runtime=runtime,
                )
                minimum_us = 0
            else:
                minimum_us = file_window.min_ms * 1_000
            file_time = cls._sample_after_within(
                anchor,
                file_upper,
                minimum_us=minimum_us,
                maximum_us=file_window.max_ms * 1_000,
                relationship_key="source.zeek_file_analyzer",
                scope=scope,
                sample_key=f"file:{ordinal}:{transfer.fuid}",
                runtime=runtime,
            )
            duration = cls._sample_file_duration(
                transfer.duration,
                source=transfer.source,
                start=file_time,
                close=observed_close,
                scope=scope,
                sample_key=f"duration:{ordinal}:{transfer.fuid}",
                runtime=runtime,
            )
            file_times[transfer.fuid] = file_time
            file_durations[transfer.fuid] = duration
            previous_file_time = file_time
            if "zeek_files" in visible_formats:
                key = network_source_timing_key("zeek_files", transfer.fuid)
                source_times[key] = file_time
                source_durations[key] = duration

        certificates = event.protocol.x509_chain or (
            (event.protocol.leaf_certificate,)
            if event.protocol.leaf_certificate is not None
            else ()
        )
        previous_certificate_file: datetime | None = None
        previous_x509: datetime | None = None
        for position, certificate in enumerate(certificates):
            anchor = ssl_time or observed_start
            if previous_certificate_file is not None:
                anchor = max(anchor, previous_certificate_file)
            certificate_file_time = cls._sample_after_within(
                anchor,
                observed_close,
                minimum_us=2_103,
                maximum_us=24_853,
                relationship_key="source.zeek_tls_certificate_file",
                scope=scope,
                sample_key=f"cert-file:{position}:{certificate.fuid}",
                runtime=runtime,
            )
            file_times[certificate.fuid] = certificate_file_time
            previous_certificate_file = certificate_file_time
            if "zeek_files" in visible_formats:
                source_times[network_source_timing_key("zeek_files", certificate.fuid)] = (
                    certificate_file_time
                )

            x509_anchor = certificate_file_time
            if previous_x509 is not None:
                x509_anchor = max(x509_anchor, previous_x509)
            x509_time = cls._sample_after_within(
                x509_anchor,
                observed_close,
                minimum_us=2_137,
                maximum_us=24_919,
                relationship_key="source.zeek_x509_analyzer",
                scope=scope,
                sample_key=f"x509:{position}:{certificate.fuid}",
                runtime=runtime,
            )
            previous_x509 = x509_time
            if "zeek_x509" in visible_formats:
                source_times[network_source_timing_key("zeek_x509", certificate.fuid)] = x509_time

        if ocsp is not None and "zeek_ocsp" in visible_formats:
            anchor = file_times.get(ocsp.id, ssl_time or observed_start)
            file_duration = file_durations.get(ocsp.id, 0.0)
            ocsp_close = (
                anchor + timedelta(seconds=file_duration) if file_duration > 0 else observed_close
            )
            source_times[network_source_timing_key("zeek_ocsp", ocsp.id)] = (
                cls._sample_after_within(
                    anchor,
                    ocsp_close,
                    minimum_us=37,
                    maximum_us=250_000,
                    relationship_key="source.zeek_ocsp_analyzer",
                    scope=scope,
                    sample_key=f"ocsp:{ocsp.id}",
                    runtime=runtime,
                )
            )

        if "zeek_pe" in visible_formats:
            for ordinal, pe in enumerate(event.protocol.pe_analyses):
                anchor = file_times.get(pe.id, observed_start)
                file_duration = file_durations.get(pe.id, 0.0)
                pe_close = (
                    anchor + timedelta(seconds=file_duration)
                    if file_duration > 0
                    else observed_close
                )
                source_times[network_source_timing_key("zeek_pe", pe.id)] = (
                    cls._sample_after_within(
                        anchor,
                        pe_close,
                        minimum_us=43,
                        maximum_us=250_000,
                        relationship_key="source.zeek_pe_analyzer",
                        scope=scope,
                        sample_key=f"pe:{ordinal}:{pe.id}",
                        runtime=runtime,
                    )
                )

        return tuple(sorted(source_times.items())), tuple(sorted(source_durations.items()))

    @classmethod
    def _project_phase_time(
        cls,
        canonical_time: datetime,
        *,
        canonical_start: datetime,
        observed_start: datetime,
        sensor_identity: str,
        timing: NetworkSensorObservationTiming,
        runtime: TimingRuntime | SourceTimingPlanningRuntime,
    ) -> datetime:
        """Project a canonical child phase through the owning sensor clock."""

        key = cls._sensor_clock_key(sensor_identity, timing.profile_name)
        spec = cls._sensor_clock_spec(timing)
        projected_start = runtime.clocks.project(canonical_start, key=key, spec=spec)
        route_delay = observed_start - projected_start
        return runtime.clocks.project(canonical_time, key=key, spec=spec) + route_delay

    @classmethod
    def _sample_after_within(
        cls,
        anchor: datetime,
        upper_bound: datetime | None,
        *,
        minimum_us: int,
        maximum_us: int,
        relationship_key: str,
        scope: TimingScope,
        sample_key: str,
        runtime: TimingRuntime | SourceTimingPlanningRuntime,
    ) -> datetime:
        """Sample right-skew analyzer slack inside the available interval."""

        minimum_us = max(0, minimum_us)
        maximum_us = max(minimum_us + 3, maximum_us)
        if upper_bound is None:
            return runtime.sampler.after(
                anchor,
                cls._right_skew_distribution(minimum_us, maximum_us),
                relationship_key=relationship_key,
                scope=scope,
                sample_key=sample_key,
            )
        available_us = round((upper_bound - anchor).total_seconds() * 1_000_000)
        if available_us <= 2:
            runtime.audit.record_saturation(f"{relationship_key}.admissible_window")
            raise TimingDistributionError(
                f"{relationship_key} has no microsecond interior before its owning close: "
                f"anchor={anchor.isoformat()} close={upper_bound.isoformat()} "
                f"available_us={available_us}"
            )
        sampled_maximum = min(maximum_us, available_us)
        sampled_minimum = min(minimum_us, max(0, sampled_maximum - 3))
        if sampled_maximum <= sampled_minimum + 2:
            sampled_minimum = 0
        try:
            return runtime.sampler.after(
                anchor,
                cls._right_skew_distribution(sampled_minimum, sampled_maximum),
                relationship_key=relationship_key,
                scope=scope,
                sample_key=f"{sample_key}:{available_us}",
            )
        except TimingDistributionError:
            runtime.audit.record_saturation(f"{relationship_key}.admissible_window")
            raise

    @classmethod
    def _sample_file_duration(
        cls,
        canonical_duration: float,
        *,
        source: str,
        start: datetime,
        close: datetime | None,
        scope: TimingScope,
        sample_key: str,
        runtime: TimingRuntime | SourceTimingPlanningRuntime,
    ) -> float:
        """Sample a file-analysis duration with interior transport-close slack."""

        if canonical_duration <= 0:
            return 0.0
        canonical_us = max(1, round(canonical_duration * 1_000_000))
        if close is None:
            maximum_us = max(canonical_us + 3, round(canonical_us * 1.45))
        else:
            available_us = round((close - start).total_seconds() * 1_000_000)
            if available_us <= 3:
                runtime.audit.record_saturation("source.zeek_file.duration_window")
                return 0.0
            cap_us = {
                "HTTP": 120_000,
                "SMB": 160_000,
                "SMTP": 280_000,
            }.get(source.upper(), 100_000)
            margin_maximum = min(cap_us, max(3, available_us // 3))
            margin = runtime.sampler.sample_microseconds(
                cls._right_skew_distribution(1, margin_maximum),
                relationship_key="source.zeek_file.close_slack",
                scope=scope,
                sample_key=f"{sample_key}:close",
            )
            maximum_us = available_us - margin
            if maximum_us <= 2:
                runtime.audit.record_saturation("source.zeek_file.duration_window")
                return 0.0
        lower_us = max(0, min(maximum_us - 2, round(canonical_us * 0.55)))
        preferred_us = min(canonical_us, max(1, round(maximum_us * 0.82)))
        upper_us = min(maximum_us, max(preferred_us + 3, round(canonical_us * 1.55)))
        if upper_us <= lower_us + 2:
            lower_us = 0
            upper_us = maximum_us
        try:
            duration_us = runtime.sampler.sample_microseconds(
                TruncatedLognormalDistribution(
                    median=float(max(1, preferred_us)),
                    sigma=0.42,
                    minimum=float(lower_us),
                    maximum=float(upper_us),
                ),
                relationship_key="source.zeek_file.duration",
                scope=scope,
                sample_key=sample_key,
            )
        except TimingDistributionError:
            runtime.audit.record_saturation("source.zeek_file.duration_window")
            duration_us = max(1, maximum_us // 2)
        return duration_us / 1_000_000

    @classmethod
    def _observed_traffic(
        cls,
        canonical: NetworkTrafficLedger,
        timing: NetworkSensorObservationTiming,
        sensor_identity: str,
        transaction_id: str,
        protocol: str,
    ) -> NetworkTrafficLedger:
        if protocol.lower() != "tcp":
            # The canonical ledger does not retain individual datagram sizes.
            # Fractional byte loss would fabricate a rewritten UDP/ICMP packet
            # while leaving packet counts and analyzer content unchanged.
            return canonical
        rng = random.Random(
            _stable_seed(
                f"network-capture-loss:{timing.profile_name}:{sensor_identity}:{transaction_id}"
            )
        )
        if (
            timing.capture_loss_probability <= 0
            or timing.capture_loss_max_fraction <= 0
            or timing.capture_loss_max_missed_bytes <= 0
            or rng.random() >= timing.capture_loss_probability
        ):
            return canonical
        orig = canonical.orig
        resp = canonical.resp
        missed_orig = 0
        missed_resp = 0
        has_orig = canonical.orig.payload_bytes > 0
        has_resp = canonical.resp.payload_bytes > 0
        if has_orig and has_resp:
            # Capture gaps usually affect one observed direction (asymmetric
            # routing, SPAN pressure, receive-buffer loss). Reserve paired gaps
            # for the smaller class of sensor-wide loss episodes.
            shape_roll = rng.random()
            lose_orig = shape_roll < 0.44 or shape_roll >= 0.88
            lose_resp = 0.44 <= shape_roll < 0.88 or shape_roll >= 0.88
        else:
            lose_orig = has_orig
            lose_resp = has_resp
        if lose_orig:
            orig, missed_orig = cls._lose_direction(canonical.orig, timing, rng)
        if lose_resp:
            resp, missed_resp = cls._lose_direction(canonical.resp, timing, rng)
        if missed_orig + missed_resp <= 0:
            return canonical
        return NetworkTrafficLedger(
            orig=orig,
            resp=resp,
            missed_orig_bytes=canonical.missed_orig_bytes + missed_orig,
            missed_resp_bytes=canonical.missed_resp_bytes + missed_resp,
        )

    @staticmethod
    def _lose_direction(
        canonical: DirectionalTrafficLedger,
        timing: NetworkSensorObservationTiming,
        rng: random.Random,
    ) -> tuple[DirectionalTrafficLedger, int]:
        if canonical.payload_bytes <= 0:
            return canonical, 0
        fraction = rng.uniform(
            timing.capture_loss_min_fraction,
            timing.capture_loss_max_fraction,
        )
        missed = min(
            canonical.payload_bytes,
            timing.capture_loss_max_missed_bytes,
            max(1, int(round(canonical.payload_bytes * fraction))),
        )
        payload = canonical.payload_bytes - missed
        lost_packets = min(
            canonical.packets,
            max(1, int(round(canonical.packets * fraction))),
        )
        packets = canonical.packets - lost_packets
        header_bytes = max(0, canonical.ip_bytes - canonical.payload_bytes)
        lost_headers = min(
            header_bytes,
            int(round(header_bytes * fraction)),
        )
        ip_bytes = canonical.ip_bytes - missed - lost_headers
        if ip_bytes > 0 and packets == 0:
            packets = 1
        return DirectionalTrafficLedger(payload, packets, max(payload, ip_bytes)), missed


RUNTIME_OWNED_ZEEK_FORMATS = frozenset(
    {
        "zeek_conn",
        "zeek_dhcp",
        "zeek_dns",
        "zeek_files",
        "zeek_http",
        "zeek_ntp",
        "zeek_ocsp",
        "zeek_pe",
        "zeek_smtp",
        "zeek_smb_files",
        "zeek_smb_mapping",
        "zeek_ssl",
        "zeek_weird",
        "zeek_x509",
    }
)


def network_observation_owns_format_timing(
    event: CanonicalOccurrence,
    format_name: str | None,
) -> bool:
    """Return whether one Zeek format has exact runtime-owned observation timing."""

    if format_name not in RUNTIME_OWNED_ZEEK_FORMATS or event.network is None:
        return False
    if event.event_type in {"connection", "dhcp_lease"}:
        return True
    prefix = f"{format_name}:"
    for observation in event.network_observations:
        if format_name not in observation.visible_formats:
            continue
        keys = (
            *(key for key, _timestamp in observation.source_times),
            *(key for key, _duration in observation.source_durations),
        )
        if any(key == format_name or key.startswith(prefix) for key in keys):
            return True
    return False


def compatibility_network_source_time(
    event: CanonicalOccurrence,
    key: str,
) -> datetime:
    """Plan one direct-caller source time outside an emitter instance.

    Production dispatch always attaches sensor observations. This adapter keeps
    low-level emitter APIs deterministic without restoring module-global
    planners or mutable emitter timing state.
    """

    if event.network is None:
        return _compatibility_context_source_time(event, key)
    interval_us = _compatibility_direct_interval_microseconds(event)
    if interval_us is not None and interval_us <= 2:
        source_times, _source_durations = _compatibility_short_protocol_timing(event)
        parent_start, parent_close = _compatibility_direct_parent_interval(event)
        return dict(source_times).get(
            key,
            parent_close if interval_us > 0 and parent_close is not None else parent_start,
        )
    try:
        source_times, _source_durations = _compatibility_protocol_timing(event)
    except TimingDistributionError as exc:
        if "has no microsecond interior before its owning close" not in str(exc):
            raise
        source_times, _source_durations = _compatibility_short_protocol_timing(event)
        return dict(source_times).get(key, ensure_utc(event.timestamp))
    return dict(source_times).get(key, ensure_utc(event.timestamp))


def compatibility_network_source_duration(
    event: CanonicalOccurrence,
    key: str,
) -> float | None:
    """Plan one direct-caller source duration outside an emitter instance."""

    interval_us = _compatibility_direct_interval_microseconds(event)
    if interval_us is not None and interval_us <= 2:
        _source_times, source_durations = _compatibility_short_protocol_timing(event)
        return dict(source_durations).get(key)
    try:
        _source_times, source_durations = _compatibility_protocol_timing(event)
    except TimingDistributionError as exc:
        if "has no microsecond interior before its owning close" not in str(exc):
            raise
        _source_times, source_durations = _compatibility_short_protocol_timing(event)
        return dict(source_durations).get(key)
    duration = dict(source_durations).get(key)
    network = event.network
    if (
        key == network_source_timing_key("zeek_conn")
        and network is not None
        and network.protocol == "tcp"
        and network.dst_port == 443
        and network.conn_state == "SF"
        and (event.protocol.ssl is not None or (network.service or "").strip().lower() == "ssl")
    ):
        return _compatibility_legacy_conn_duration(event)
    return duration


def _compatibility_direct_interval_microseconds(event: CanonicalOccurrence) -> int | None:
    """Return a closed direct transport interval in whole microseconds."""

    network = event.network
    if network is None or network.duration is None:
        return None
    return max(0, round(float(network.duration) * 1_000_000))


def _compatibility_direct_network_seed(event: CanonicalOccurrence) -> tuple[object, ...]:
    """Return the exact pre-migration direct Zeek timing seed."""

    network = event.network
    if network is None:
        return (event.timestamp,)
    return (
        network.zeek_uid,
        network.src_ip,
        network.src_port,
        network.dst_ip,
        network.dst_port,
        event.timestamp,
    )


def _compatibility_direct_parent_interval(
    event: CanonicalOccurrence,
) -> tuple[datetime, datetime | None]:
    """Return the legacy direct interval anchored to the occurrence timestamp."""

    parent_start = ensure_utc(event.timestamp)
    network = event.network
    duration = network.duration if network is not None else None
    parent_close = parent_start + timedelta(seconds=duration) if duration is not None else None
    return parent_start, parent_close


def _compatibility_detached_event(event: CanonicalOccurrence) -> CanonicalOccurrence:
    """Return an event-local timing carrier without mutating caller-owned state."""

    return replace(
        event,
        source_timing=SourceTimingPlan(canonical_timestamp=ensure_utc(event.timestamp)),
    )


def _compatibility_legacy_http_time(
    event: CanonicalOccurrence,
    planner: SourceTimingPlanner,
) -> datetime:
    """Reproduce the parent direct HTTP timestamp for a non-interior interval."""

    network = event.network
    http = event.protocol.http
    if network is None or http is None:
        return ensure_utc(event.timestamp)
    seed = _compatibility_direct_network_seed(event)
    canonical_request_time = http.canonical_request_time
    if canonical_request_time is not None:
        connection_time = network.started_at
        planned_close = network.closed_at
    else:
        connection_time = planner.source_time(
            event,
            "source.zeek_conn_start",
            seed_parts=seed,
            not_before=event.timestamp,
        )
        planned_close = None
    within: tuple[datetime, datetime] | None = None
    latest_time: datetime | None = None
    has_files = bool(http.orig_fuids or http.resp_fuids)
    tail_gap = timedelta(milliseconds=2) if has_files else timedelta(microseconds=1)
    if planned_close is not None:
        latest_time = max(connection_time, planned_close - tail_gap)
        within = (connection_time, latest_time)
    elif network.duration is not None and network.duration > 0:
        latest_time = max(
            connection_time,
            connection_time + timedelta(seconds=network.duration) - tail_gap,
        )
        within = (connection_time, latest_time)

    request_not_before = max(connection_time, canonical_request_time or connection_time)
    if canonical_request_time is not None:
        timestamp = max(connection_time, canonical_request_time)
        if latest_time is not None:
            timestamp = min(timestamp, latest_time)
    else:
        timestamp = planner.source_time(
            event,
            "source.zeek_http_request",
            seed_parts=seed,
            not_before=request_not_before,
            within=within,
        )
    timestamp = planner.packet_child_time(
        event,
        "source.zeek_http_request",
        seed_parts=seed,
        preferred_time=timestamp,
        not_before=request_not_before,
        within=within,
    )
    planner.record_source_time(
        event,
        "source.zeek_http_request",
        timestamp,
        seed_parts=seed,
    )
    return timestamp


def _compatibility_legacy_conn_time(
    event: CanonicalOccurrence,
    planner: SourceTimingPlanner,
) -> datetime:
    """Return the parent direct conn.log timestamp."""

    return planner.source_time(
        event,
        "source.zeek_conn_start",
        seed_parts=_compatibility_direct_network_seed(event),
        not_before=event.timestamp,
    )


def _compatibility_legacy_conn_duration(event: CanonicalOccurrence) -> float | None:
    """Return the parent direct conn.log duration, including its TLS floor."""

    network = event.network
    if network is None:
        return None
    duration = network.duration
    is_completed_tls = (
        network.protocol == "tcp"
        and network.dst_port == 443
        and network.conn_state == "SF"
        and (event.protocol.ssl is not None or (network.service or "").strip().lower() == "ssl")
    )
    if not is_completed_tls:
        return duration
    window = get_timing_window(
        "network.tls_completed_min_duration",
        default_min_ms=800,
        default_max_ms=2500,
        default_position="after",
        default_class="same_observation",
    )
    minimum = window.min_ms / 1_000
    if (
        duration is not None
        and duration >= minimum
        and abs(duration - minimum) >= 0.000001
        and not (
            (network.service or "").strip().lower() == "ssl" and abs(duration - 1.2) < 0.000001
        )
    ):
        return duration
    span_ms = max(1, window.max_ms - window.min_ms)
    seed = _stable_seed(
        "zeek_tls_duration_floor:"
        f"{network.zeek_uid}:{network.src_ip}:{network.src_port}:"
        f"{network.dst_ip}:{network.dst_port}:{event.timestamp.isoformat()}"
    )
    sampled = (window.min_ms + 1 + (seed % span_ms)) / 1_000
    return max(sampled, float(duration or 0.0) + 0.001)


def _compatibility_legacy_tls_times(
    event: CanonicalOccurrence,
    planner: SourceTimingPlanner,
) -> tuple[datetime, tuple[datetime, datetime] | None, datetime]:
    """Return the parent direct connection bounds and SSL analyzer time."""

    network = event.network
    if network is None:
        timestamp = ensure_utc(event.timestamp)
        return timestamp, None, timestamp
    conn_time = _compatibility_legacy_conn_time(event, planner)
    within: tuple[datetime, datetime] | None = None
    if network.duration is not None and network.duration > 0:
        latest = conn_time + timedelta(seconds=max(0.0, network.duration - 0.000001))
        within = (conn_time, latest)
    ssl_time = planner.source_time(
        event,
        "source.zeek_ssl_analyzer",
        seed_parts=_compatibility_direct_network_seed(event),
        not_before=conn_time,
        within=within,
    )
    return conn_time, within, ssl_time


def _compatibility_tls_certificate_gap(
    event: CanonicalOccurrence,
    fuid: str,
    position: int,
    label: str,
) -> timedelta:
    """Return the exact parent deterministic TLS certificate spacing."""

    seed = _stable_seed(
        "zeek-tls-cert-gap:"
        f"{label}:{getattr(event.network, 'zeek_uid', '')}:{fuid}:"
        f"{position}:{event.timestamp.isoformat()}"
    )
    return timedelta(milliseconds=2 + (seed % 23), microseconds=103 + ((seed >> 8) % 853))


def _compatibility_bound_in_connection(
    conn_time: datetime,
    conn_duration: float | None,
    preferred_time: datetime,
) -> datetime:
    """Apply the parent source-side analyzer timestamp bound."""

    if conn_duration is None or conn_duration <= 0:
        return max(conn_time, preferred_time)
    conn_end = conn_time + timedelta(seconds=conn_duration)
    latest = conn_end - timedelta(milliseconds=1)
    if preferred_time > latest:
        return latest if latest > conn_time else conn_time
    return max(conn_time, preferred_time)


def _compatibility_constrained_tls_time(
    event: CanonicalOccurrence,
    planner: SourceTimingPlanner,
    source_key: str,
    seed_parts: tuple[Any, ...],
    lower_bound: datetime,
    conn_time: datetime,
    within: tuple[datetime, datetime] | None,
) -> datetime:
    """Apply the parent TLS ordering and connection constraints."""

    if within is not None and lower_bound > within[1]:
        lower_bound = within[1]
    preferred = planner.source_time(
        event,
        source_key,
        seed_parts=seed_parts,
        not_before=lower_bound,
        within=within,
    )
    duration = event.network.duration if event.network is not None else None
    timestamp = _compatibility_bound_in_connection(conn_time, duration, preferred)
    return lower_bound if timestamp < lower_bound else timestamp


def _compatibility_legacy_certificate_file_time(
    event: CanonicalOccurrence,
    planner: SourceTimingPlanner,
    certificate: Any,
    position: int,
    previous_time: datetime | None,
) -> datetime:
    """Return the parent direct files.log timestamp for one certificate."""

    network = event.network
    gap = _compatibility_tls_certificate_gap(event, certificate.fuid, position, "file")
    if network is None:
        lower = event.timestamp if previous_time is None else previous_time + gap
        return planner.source_time(
            event,
            "source.zeek_file_analyzer",
            seed_parts=("tls-cert-file", certificate.fuid, position, event.timestamp),
            not_before=lower,
        )
    conn_time, within, ssl_time = _compatibility_legacy_tls_times(event, planner)
    lower = ssl_time + gap
    if previous_time is not None:
        lower = max(lower, previous_time + gap)
    return _compatibility_constrained_tls_time(
        event,
        planner,
        "source.zeek_file_analyzer",
        (network.zeek_uid, "tls-cert-file", certificate.fuid, position, event.timestamp),
        lower,
        conn_time,
        within,
    )


def _compatibility_legacy_x509_time(
    event: CanonicalOccurrence,
    planner: SourceTimingPlanner,
    certificate: Any,
    position: int,
    file_time: datetime,
    previous_time: datetime | None,
) -> datetime:
    """Return the parent direct x509.log timestamp for one certificate."""

    network = event.network
    gap = _compatibility_tls_certificate_gap(event, certificate.fuid, position, "x509")
    lower = file_time + gap
    if previous_time is not None:
        lower = max(lower, previous_time + gap)
    if network is None:
        return planner.source_time(
            event,
            "source.zeek_x509_analyzer",
            seed_parts=("tls-cert-x509", certificate.fuid, position, event.timestamp),
            not_before=lower,
        )
    conn_time, within, _ssl_time = _compatibility_legacy_tls_times(event, planner)
    return _compatibility_constrained_tls_time(
        event,
        planner,
        "source.zeek_x509_analyzer",
        (network.zeek_uid, "tls-cert-x509", certificate.fuid, position, event.timestamp),
        lower,
        conn_time,
        within,
    )


def _compatibility_related_http_time(
    event: CanonicalOccurrence,
    planner: SourceTimingPlanner,
    transfer: Any,
) -> datetime | None:
    """Return the parent files-only HTTP analyzer anchor for one transfer."""

    network = event.network
    http = event.protocol.http
    if network is None or http is None or transfer.fuid not in (*http.orig_fuids, *http.resp_fuids):
        return None
    conn_time = _compatibility_legacy_conn_time(event, planner)
    return planner.source_time(
        event,
        "source.zeek_http_request",
        seed_parts=_compatibility_direct_network_seed(event),
        not_before=conn_time,
    ) + timedelta(milliseconds=1)


def _compatibility_legacy_file_analyzer_time(
    event: CanonicalOccurrence,
    planner: SourceTimingPlanner,
    transfer: Any,
    conn_time: datetime,
) -> datetime:
    """Return the parent unbounded files.log analyzer timestamp."""

    network = event.network
    if network is None:
        return ensure_utc(event.timestamp)
    seed_parts = (network.zeek_uid, transfer.fuid, event.timestamp)
    if event.protocol.http is not None:
        return planner.source_time_after_source(
            event,
            "source.zeek_file_analyzer",
            after_source_key="source.zeek_http_request",
            gap_key="source.zeek_file_analyzer",
            seed_parts=seed_parts,
            after_seed_parts=_compatibility_direct_network_seed(event),
            after_not_before=conn_time,
            not_before=conn_time + timedelta(milliseconds=1),
        )
    return planner.source_time(
        event,
        "source.zeek_file_analyzer",
        seed_parts=seed_parts,
        not_before=conn_time + timedelta(milliseconds=1),
    )


def _compatibility_legacy_transfer_observation(
    event: CanonicalOccurrence,
    planner: SourceTimingPlanner,
    transfer: Any,
    min_start: datetime | None,
) -> tuple[datetime, float]:
    """Return parent zero-flow file timing or the legal short-flow endpoint."""

    interval_us = _compatibility_direct_interval_microseconds(event)
    if interval_us is not None and interval_us > 0:
        _parent_start, parent_close = _compatibility_direct_parent_interval(event)
        if parent_close is not None:
            return parent_close, 0.0
    conn_time = _compatibility_legacy_conn_time(event, planner)
    timestamp = _compatibility_legacy_file_analyzer_time(
        event,
        planner,
        transfer,
        conn_time,
    )
    lower = max(conn_time, min_start) if min_start is not None else conn_time
    if transfer.observation_not_before is not None:
        lower = max(lower, transfer.observation_not_before)
    return max(timestamp, lower), transfer.duration


def _compatibility_legacy_files_timing(
    event: CanonicalOccurrence,
) -> tuple[dict[str, datetime], dict[str, float]]:
    """Replay the parent files.log loop once without emitter-local state."""

    detached = _compatibility_detached_event(event)
    planner = SourceTimingPlanner()
    times: dict[str, datetime] = {}
    durations: dict[str, float] = {}
    previous_transfer: datetime | None = None
    transfers = sorted(detached.protocol.file_transfers, key=lambda transfer: not transfer.is_orig)
    for transfer in transfers:
        minimum = _compatibility_related_http_time(detached, planner, transfer)
        if previous_transfer is not None:
            next_minimum = previous_transfer + timedelta(microseconds=100)
            minimum = max(minimum, next_minimum) if minimum is not None else next_minimum
        timestamp, duration = _compatibility_legacy_transfer_observation(
            detached,
            planner,
            transfer,
            minimum,
        )
        key = network_source_timing_key("zeek_files", transfer.fuid)
        times[key] = timestamp
        durations[key] = duration
        previous_transfer = timestamp

    previous_certificate: datetime | None = None
    for position, certificate in enumerate(detached.protocol.x509_chain):
        timestamp = _compatibility_legacy_certificate_file_time(
            detached,
            planner,
            certificate,
            position,
            previous_certificate,
        )
        times[network_source_timing_key("zeek_files", certificate.fuid)] = timestamp
        previous_certificate = timestamp
    return times, durations


def _compatibility_legacy_x509_timing(event: CanonicalOccurrence) -> dict[str, datetime]:
    """Replay the parent x509.log loop once without emitter-local state."""

    detached = _compatibility_detached_event(event)
    planner = SourceTimingPlanner()
    certificates = detached.protocol.x509_chain or (
        (detached.protocol.leaf_certificate,)
        if detached.protocol.leaf_certificate is not None
        else ()
    )
    times: dict[str, datetime] = {}
    previous_file: datetime | None = None
    previous_x509: datetime | None = None
    for position, certificate in enumerate(certificates):
        file_time = _compatibility_legacy_certificate_file_time(
            detached,
            planner,
            certificate,
            position,
            previous_file,
        )
        x509_time = _compatibility_legacy_x509_time(
            detached,
            planner,
            certificate,
            position,
            file_time,
            previous_x509,
        )
        times[network_source_timing_key("zeek_x509", certificate.fuid)] = x509_time
        previous_file = file_time
        previous_x509 = x509_time
    return times


def _compatibility_legacy_ocsp_time(event: CanonicalOccurrence) -> tuple[str, datetime] | None:
    """Return the parent direct OCSP row key and timestamp."""

    ocsp = event.protocol.ocsp
    if ocsp is None:
        return None
    detached = _compatibility_detached_event(event)
    planner = SourceTimingPlanner()
    transfer = detached.protocol.primary_file_transfer
    if detached.network is not None and transfer is not None:
        minimum = _compatibility_related_http_time(detached, planner, transfer)
        file_time, file_duration = _compatibility_legacy_transfer_observation(
            detached,
            planner,
            transfer,
            minimum,
        )
        duration_us = max(0, int(file_duration * 1_000_000))
        if duration_us <= 1:
            timestamp = file_time
        else:
            offset_us = 1 + (
                _stable_seed(f"zeek_ocsp_ts:{ocsp.id}:{detached.network.zeek_uid}")
                % (duration_us - 1)
            )
            timestamp = file_time + timedelta(microseconds=offset_us)
    else:
        delay_ms = 1 + (_stable_seed(f"zeek_ocsp_ts:{ocsp.id}") % 8)
        timestamp = ensure_utc(detached.timestamp) + timedelta(milliseconds=delay_ms)
        interval_us = _compatibility_direct_interval_microseconds(detached)
        if interval_us is not None and interval_us > 0:
            _parent_start, parent_close = _compatibility_direct_parent_interval(detached)
            if parent_close is not None:
                timestamp = min(timestamp, parent_close)
    return network_source_timing_key("zeek_ocsp", ocsp.id), timestamp


def _compatibility_legacy_pe_timing(event: CanonicalOccurrence) -> dict[str, datetime]:
    """Return the parent direct PE analyzer timestamps."""

    detached = _compatibility_detached_event(event)
    planner = SourceTimingPlanner()
    times: dict[str, datetime] = {}
    for pe in detached.protocol.pe_analyses:
        transfer = next(
            (
                candidate
                for candidate in detached.protocol.file_transfers
                if candidate.fuid == pe.id
            ),
            None,
        )
        if detached.network is not None and transfer is not None:
            minimum = _compatibility_related_http_time(detached, planner, transfer)
            file_time, file_duration = _compatibility_legacy_transfer_observation(
                detached,
                planner,
                transfer,
                minimum,
            )
            duration_us = max(0, int(file_duration * 1_000_000))
            if duration_us <= 1:
                timestamp = file_time
            else:
                maximum_offset = min(duration_us - 1, 250_000)
                offset_us = 1 + (
                    _stable_seed(f"zeek_pe_ts:{pe.id}:{detached.network.zeek_uid}") % maximum_offset
                )
                timestamp = file_time + timedelta(microseconds=offset_us)
        else:
            timestamp = ensure_utc(detached.timestamp) + timedelta(milliseconds=1)
            interval_us = _compatibility_direct_interval_microseconds(detached)
            if interval_us is not None and interval_us > 0:
                _parent_start, parent_close = _compatibility_direct_parent_interval(detached)
                if parent_close is not None:
                    timestamp = min(timestamp, parent_close)
        times[network_source_timing_key("zeek_pe", pe.id)] = timestamp
    return times


def _compatibility_short_protocol_timing(
    event: CanonicalOccurrence,
) -> tuple[tuple[tuple[str, datetime], ...], tuple[tuple[str, float], ...]]:
    """Reproduce supported zero-flow rows and safely bridge positive microflows."""

    network = event.network
    if network is None:
        return (), ()
    source_times: dict[str, datetime] = {}
    source_durations: dict[str, float] = {}

    conn_event = _compatibility_detached_event(event)
    source_times[network_source_timing_key("zeek_conn")] = _compatibility_legacy_conn_time(
        conn_event,
        SourceTimingPlanner(),
    )
    conn_duration = _compatibility_legacy_conn_duration(conn_event)
    if conn_duration is not None:
        source_durations[network_source_timing_key("zeek_conn")] = conn_duration

    if event.protocol.http is not None:
        http_event = _compatibility_detached_event(event)
        source_times[network_source_timing_key("zeek_http")] = _compatibility_legacy_http_time(
            http_event,
            SourceTimingPlanner(),
        )
    if event.protocol.ssl is not None:
        ssl_event = _compatibility_detached_event(event)
        _conn_time, _within, ssl_time = _compatibility_legacy_tls_times(
            ssl_event,
            SourceTimingPlanner(),
        )
        source_times[network_source_timing_key("zeek_ssl")] = ssl_time

    file_times, file_durations = _compatibility_legacy_files_timing(event)
    source_times.update(file_times)
    source_durations.update(file_durations)
    source_times.update(_compatibility_legacy_x509_timing(event))
    ocsp_timing = _compatibility_legacy_ocsp_time(event)
    if ocsp_timing is not None:
        source_times[ocsp_timing[0]] = ocsp_timing[1]
    source_times.update(_compatibility_legacy_pe_timing(event))
    interval_us = _compatibility_direct_interval_microseconds(event)
    if interval_us is not None and interval_us > 0:
        parent_start, parent_close = _compatibility_direct_parent_interval(event)
        if parent_close is not None:
            source_times = {
                key: min(parent_close, max(parent_start, timestamp))
                for key, timestamp in source_times.items()
            }
            source_durations = {
                key: min(
                    max(0.0, duration),
                    max(
                        0.0,
                        (parent_close - source_times.get(key, parent_start)).total_seconds(),
                    ),
                )
                for key, duration in source_durations.items()
            }
    return tuple(sorted(source_times.items())), tuple(sorted(source_durations.items()))


def _compatibility_protocol_timing(
    event: CanonicalOccurrence,
) -> tuple[tuple[tuple[str, datetime], ...], tuple[tuple[str, float], ...]]:
    """Return one stateless direct-emitter protocol timing plan."""

    network = event.network
    if network is None:
        return (), ()
    canonical_start = ensure_utc(event.timestamp)
    observed_close = (
        canonical_start + timedelta(seconds=network.duration)
        if network.duration is not None
        else None
    )
    runtime = _compatibility_runtime(event)
    timing = network_sensor_observation_timing("well_synced")
    return NetworkObservationPlanner._source_native_protocol_timing(
        event,
        canonical_start=canonical_start,
        observed_start=canonical_start,
        observed_close=observed_close,
        sensor_identity="__direct__",
        path_role="direct",
        visible_formats=set(RUNTIME_OWNED_ZEEK_FORMATS),
        timing=timing,
        runtime=runtime,
    )


def _compatibility_context_source_time(
    event: CanonicalOccurrence,
    key: str,
) -> datetime:
    """Plan direct protocol-context timing when no transport was supplied."""

    runtime = _compatibility_runtime(event)
    scope = _compatibility_scope(event)
    anchor = ensure_utc(event.timestamp)
    ssl_time = NetworkObservationPlanner._sample_after_within(
        anchor,
        None,
        minimum_us=3_000,
        maximum_us=650_000,
        relationship_key="source.zeek_ssl_analyzer",
        scope=scope,
        sample_key="ssl",
        runtime=runtime,
    )
    if key == network_source_timing_key("zeek_ssl"):
        return ssl_time
    certificates = event.protocol.x509_chain or (
        (event.protocol.leaf_certificate,) if event.protocol.leaf_certificate is not None else ()
    )
    previous_file = ssl_time
    previous_x509 = ssl_time
    for position, certificate in enumerate(certificates):
        file_time = NetworkObservationPlanner._sample_after_within(
            previous_file,
            None,
            minimum_us=2_103,
            maximum_us=24_853,
            relationship_key="source.zeek_tls_certificate_file",
            scope=scope,
            sample_key=f"cert-file:{position}:{certificate.fuid}",
            runtime=runtime,
        )
        x509_time = NetworkObservationPlanner._sample_after_within(
            max(file_time, previous_x509),
            None,
            minimum_us=2_137,
            maximum_us=24_919,
            relationship_key="source.zeek_x509_analyzer",
            scope=scope,
            sample_key=f"x509:{position}:{certificate.fuid}",
            runtime=runtime,
        )
        if key == network_source_timing_key("zeek_files", certificate.fuid):
            return file_time
        if key == network_source_timing_key("zeek_x509", certificate.fuid):
            return x509_time
        previous_file = file_time
        previous_x509 = x509_time
    return anchor


def _compatibility_runtime(event: CanonicalOccurrence) -> TimingRuntime:
    reference = ensure_utc(event.timestamp).replace(hour=0, minute=0, second=0, microsecond=0)
    return TimingRuntime(reference_time=reference)


def _compatibility_scope(event: CanonicalOccurrence) -> TimingScope:
    network = event.network
    return TimingScope(
        stable_id=(
            network.stable_id or network.zeek_uid
            if network is not None
            else event.timestamp.isoformat()
        ),
        source="__direct__",
        lifecycle_id="direct",
    )
