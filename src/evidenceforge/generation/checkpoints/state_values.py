"""Explicit safe value codec for the StateManager bounded checkpoint head.

Only the runtime value classes named in this module are accepted. There is no arbitrary
dataclass, ``__dict__``, import, or object-graph fallback.
"""

from __future__ import annotations

import random
from dataclasses import fields
from datetime import datetime, timedelta

from pydantic import TypeAdapter, ValidationError

from evidenceforge.events.application import ApplicationChannelBudget, ApplicationTransportBinding
from evidenceforge.events.identity import (
    MacosAuditSession,
    MacosProcessAuditBinding,
    MacosProcessPrivilegeDrop,
    MacosProcessServiceDrop,
    PosixProcessCredentials,
    ProcessIdentity,
    SessionIdentity,
    ThreadIdentity,
)
from evidenceforge.events.job_control import (
    PosixGroupIdentity,
    PosixJobControlChange,
    PosixJobControlReservation,
    PosixSessionIdentity,
)
from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.events.macos_runtime import MacosImageSecurity
from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    FileSensorObservation,
    NatSensorObservation,
    NetworkSensorObservation,
    NetworkTrafficLedger,
    NetworkTransactionPlan,
    NetworkTuple,
)
from evidenceforge.events.parentage import (
    ProcessParentage,
    ProcessParentageChange,
    ProcessParentReference,
)
from evidenceforge.events.process_outcome import PosixProcessExit
from evidenceforge.events.rdp import (
    RdpLogicalSessionIdentity,
    RdpRetentionLease,
    RdpSessionAffinity,
    RdpSessionSnapshot,
    RdpSessionState,
    RdpTransportGeneration,
)
from evidenceforge.events.responsibility import ProcessResponsibility, ResponsibleProcessReference
from evidenceforge.generation.activity.public_identity_profiles import PublicIdentityBinding
from evidenceforge.generation.process_runtime_cache import RuntimeProcessBinding
from evidenceforge.models.state import (
    ActiveSession,
    OpenConnection,
    RunningProcess,
    RunningThread,
    SmbFileState,
)

from .errors import CheckpointCorruptionError
from .packed import dumps
from .rng import decode_random_state, encode_random_state

_ACTIVE_SESSION_FIELDS = (
    "logon_id",
    "username",
    "system",
    "logon_type",
    "start_time",
    "source_ip",
    "session_id",
    "explorer_pid",
    "windows_shell_bootstrapped",
    "initial_explorer_pid",
    "session_shell_pid",
    "session_user_manager_pid",
    "session_winlogon_pid",
    "login_occurrence_emitted",
    "process_tree_root",
    "last_activity_time",
    "network_close_time",
    "source_ready_time",
    "source_port",
    "session_kind",
    "transport_pid",
    "closure_owned_by_bundle",
    "ecar_object_id",
    "storyline_protected",
    "logon_guid",
    "lifecycle_group_id",
    "parent_lifecycle_group_id",
    "end_plan",
    "auth_protocol",
    "smb_principal",
    "account_scope",
    "auth_session_ref",
    "effective_uid",
    "effective_gid",
    "audit_origin",
)
_RUNNING_PROCESS_FIELDS = (
    "pid",
    "parent_pid",
    "image",
    "command_line",
    "username",
    "system",
    "start_time",
    "integrity_level",
    "last_activity_time",
    "logon_id",
    "token_logon_id",
    "auth_session_id",
    "auth_logon_type",
    "ecar_object_id",
    "story_created",
    "primary_tid",
    "lifecycle_group_id",
    "parent_lifecycle_group_id",
    "concurrency_group_id",
    "pid_logical_position",
    "end_time",
    "execution_ordinal",
    "executed_at",
    "prior_executions",
    "lifetime_image",
    "credentials",
    "audit_pid_version",
    "audit_binding",
    "privilege_drop",
    "service_drop",
    "exit_outcome",
    "arguments",
    "job_control",
    "job_control_history",
    "environment",
    "parentage",
    "parentage_history",
    "responsibility",
    "image_security",
)
_RUNNING_THREAD_FIELDS = (
    "hostname",
    "process_object_id",
    "pid",
    "tid",
    "object_id",
    "start_time",
    "kind",
    "end_time",
)
_OPEN_CONNECTION_FIELDS = (
    "conn_id",
    "zeek_uid",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "state",
    "start_time",
    "source_system",
    "source_hostname",
    "hostname",
    "initiating_pid",
    "close_time",
    "bytes_sent",
    "bytes_received",
    "traffic_ledger",
    "transaction_id",
    "conn_state",
    "history",
    "duration",
)
_SMB_FILE_STATE_FIELDS = (
    "file_id",
    "share",
    "path",
    "version",
    "size_bytes",
    "mime_type",
    "tags",
    "deleted",
    "prior_paths",
)
_SESSION_END_PLAN_FIELDS = ("canonical_end", "authority", "storyline_event_id")
_DIRECTIONAL_TRAFFIC_FIELDS = ("payload_bytes", "packets", "ip_bytes")
_NETWORK_TRAFFIC_FIELDS = ("orig", "resp", "missed_orig_bytes", "missed_resp_bytes")
_NETWORK_TUPLE_FIELDS = ("src_ip", "src_port", "dst_ip", "dst_port", "protocol")
_NAT_SENSOR_OBSERVATION_FIELDS = (
    "nat_type",
    "direction",
    "local_ip",
    "local_port",
    "global_ip",
    "global_port",
    "built_time",
    "teardown_time",
)
_FILE_SENSOR_OBSERVATION_FIELDS = (
    "canonical_id",
    "seen_bytes",
    "total_bytes",
    "missing_bytes",
    "analyzers_visible",
)
_NETWORK_SENSOR_OBSERVATION_FIELDS = (
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
_APPLICATION_CHANNEL_BUDGET_FIELDS = ("initiator_bytes", "responder_bytes", "operations")
_APPLICATION_TRANSPORT_BINDING_FIELDS = ("transport_id", "opened_at", "closes_at")
_RDP_SESSION_AFFINITY_FIELDS = (
    "source_host",
    "source_address",
    "target_host",
    "target_address",
    "principal",
    "logon_id",
    "session_id",
    "digest",
)
_RDP_LOGICAL_SESSION_IDENTITY_FIELDS = (
    "logical_session_id",
    "affinity",
    "started_at",
    "idle_timeout",
    "reconnect_timeout",
    "hard_deadline",
    "budget",
)
_RDP_TRANSPORT_GENERATION_FIELDS = (
    "ordinal",
    "channel_id",
    "binding",
    "connected_at",
    "idle_deadline",
    "disconnected_at",
)
_RDP_RETENTION_LEASE_FIELDS = (
    "lease_id",
    "logical_session_id",
    "acquired_at",
    "retain_until",
    "reason",
)
_RDP_SESSION_SNAPSHOT_FIELDS = (
    "identity",
    "state",
    "generation",
    "last_transition_at",
    "reconnect_deadline",
    "logged_out_at",
    "retention_deadline",
    "reserved_initiator_bytes",
    "reserved_responder_bytes",
    "reserved_operations",
    "completed_operations",
    "active_operations",
    "member_admissions",
    "dependent_admissions",
    "active_leases",
)
_RUNTIME_PROCESS_BINDING_FIELDS = ("pid", "process_key")
_PUBLIC_IDENTITY_BINDING_FIELDS = (
    "semantic_key",
    "ip",
    "role",
    "provider",
    "forward_names",
    "ptr",
    "tls_profile",
    "traits",
    "authored",
    "provenance",
    "fingerprint",
)
_THREAD_IDENTITY_FIELDS = (
    "hostname",
    "process_object_id",
    "pid",
    "tid",
    "object_id",
    "started_at",
    "kind",
)
_PROCESS_IDENTITY_FIELDS = (
    "hostname",
    "object_id",
    "pid",
    "parent_pid",
    "image",
    "command_line",
    "principal",
    "logon_id",
    "started_at",
    "lifecycle_group_id",
    "parent_lifecycle_group_id",
    "primary_thread",
    "execution_ordinal",
    "executed_at",
    "lifetime_image",
    "credentials",
    "audit_pid_version",
    "arguments",
    "job_control",
    "environment",
    "parentage",
    "responsibility",
    "image_security",
)
_SESSION_IDENTITY_FIELDS = (
    "hostname",
    "object_id",
    "logon_id",
    "session_id",
    "principal",
    "session_kind",
    "started_at",
    "lifecycle_group_id",
    "logon_guid",
    "parent_lifecycle_group_id",
)
_NETWORK_TRANSACTION_PLAN_FIELDS = (
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

_SCHEMAS: dict[str, tuple[type[object], tuple[str, ...]]] = {
    "active-session-v2": (ActiveSession, _ACTIVE_SESSION_FIELDS),
    "macos-process-privilege-drop-v1": (
        MacosProcessPrivilegeDrop,
        (
            "origin",
            "before",
            "after",
            "before_principal",
            "after_principal",
            "before_integrity",
            "after_integrity",
            "dropped_at",
        ),
    ),
    "macos-process-service-drop-v1": (
        MacosProcessServiceDrop,
        (
            "parent_object_id",
            "parent_execution_id",
            "execution_ordinal",
            "before",
            "after",
            "before_principal",
            "after_principal",
            "before_integrity",
            "after_integrity",
            "dropped_at",
        ),
    ),
    "macos-process-audit-binding-v1": (
        MacosProcessAuditBinding,
        ("origin", "before", "after", "bound_at"),
    ),
    "macos-audit-session-v1": (MacosAuditSession, ("audit_uid", "audit_session_id", "created_at")),
    "application-channel-budget": (
        ApplicationChannelBudget,
        _APPLICATION_CHANNEL_BUDGET_FIELDS,
    ),
    "application-transport-binding": (
        ApplicationTransportBinding,
        _APPLICATION_TRANSPORT_BINDING_FIELDS,
    ),
    "directional-traffic": (DirectionalTrafficLedger, _DIRECTIONAL_TRAFFIC_FIELDS),
    "file-sensor-observation": (FileSensorObservation, _FILE_SENSOR_OBSERVATION_FIELDS),
    "nat-sensor-observation": (NatSensorObservation, _NAT_SENSOR_OBSERVATION_FIELDS),
    "network-sensor-observation": (
        NetworkSensorObservation,
        _NETWORK_SENSOR_OBSERVATION_FIELDS,
    ),
    "network-traffic": (NetworkTrafficLedger, _NETWORK_TRAFFIC_FIELDS),
    "network-transaction-plan": (NetworkTransactionPlan, _NETWORK_TRANSACTION_PLAN_FIELDS),
    "network-tuple": (NetworkTuple, _NETWORK_TUPLE_FIELDS),
    "open-connection": (OpenConnection, _OPEN_CONNECTION_FIELDS),
    "public-identity-binding": (PublicIdentityBinding, _PUBLIC_IDENTITY_BINDING_FIELDS),
    "posix-session-v1": (
        PosixSessionIdentity,
        ("hostname", "sid", "leader_object_id", "started_at"),
    ),
    "posix-group-v1": (PosixGroupIdentity, ("session", "pgid", "leader_object_id", "started_at")),
    "posix-job-control-change-v1": (
        PosixJobControlChange,
        ("operation", "before", "after", "changed_at"),
    ),
    "posix-job-control-reservation-v1": (
        PosixJobControlReservation,
        ("identity", "members", "updated_at", "ended_at"),
    ),
    "process-parent-reference-v1": (
        ProcessParentReference,
        ("hostname", "object_id", "pid", "started_at"),
    ),
    "responsible-process-reference-v1": (
        ResponsibleProcessReference,
        ("hostname", "object_id", "pid", "started_at"),
    ),
    "macos-image-security-v1": (
        MacosImageSecurity,
        ("codesigning_flags", "is_platform_binary", "validation_category"),
    ),
    "process-responsibility-v1": (ProcessResponsibility, ("responsible",)),
    "process-parentage-v1": (ProcessParentage, ("original", "current")),
    "process-parentage-change-v1": (ProcessParentageChange, ("before", "after", "changed_at")),
    "running-process-v15": (RunningProcess, _RUNNING_PROCESS_FIELDS),
    "posix-process-exit-v1": (PosixProcessExit, ("exit_code", "signal", "core_dumped")),
    "running-thread": (RunningThread, _RUNNING_THREAD_FIELDS),
    "rdp-logical-session-identity": (
        RdpLogicalSessionIdentity,
        _RDP_LOGICAL_SESSION_IDENTITY_FIELDS,
    ),
    "rdp-retention-lease": (RdpRetentionLease, _RDP_RETENTION_LEASE_FIELDS),
    "rdp-session-affinity": (RdpSessionAffinity, _RDP_SESSION_AFFINITY_FIELDS),
    "rdp-session-snapshot": (RdpSessionSnapshot, _RDP_SESSION_SNAPSHOT_FIELDS),
    "rdp-transport-generation": (
        RdpTransportGeneration,
        _RDP_TRANSPORT_GENERATION_FIELDS,
    ),
    "runtime-process-binding": (
        RuntimeProcessBinding,
        _RUNTIME_PROCESS_BINDING_FIELDS,
    ),
    "process-identity-v10": (ProcessIdentity, _PROCESS_IDENTITY_FIELDS),
    "posix-process-credentials-v1": (
        PosixProcessCredentials,
        ("real_uid", "effective_uid", "real_gid", "effective_gid", "audit_uid", "audit_session_id"),
    ),
    "session-identity": (SessionIdentity, _SESSION_IDENTITY_FIELDS),
    "session-end-plan": (SessionEndPlan, _SESSION_END_PLAN_FIELDS),
    "smb-file-state": (SmbFileState, _SMB_FILE_STATE_FIELDS),
    "thread-identity": (ThreadIdentity, _THREAD_IDENTITY_FIELDS),
}
_TAGS_BY_TYPE = {value_type: tag for tag, (value_type, _names) in _SCHEMAS.items()}
_ADAPTERS = {tag: TypeAdapter(value_type) for tag, (value_type, _names) in _SCHEMAS.items()}

for _tag, (_value_type, _field_names) in _SCHEMAS.items():
    if tuple(field.name for field in fields(_value_type)) != _field_names:
        raise RuntimeError(f"checkpoint schema for {_tag} does not match its runtime dataclass")


def _sort_encoded(values: list[object]) -> list[object]:
    return sorted(values, key=dumps)


def encode_state_value(value: object) -> object:
    """Encode one allowlisted StateManager value into inert primitives."""

    if value is None or type(value) in {bool, int, float, str, bytes}:
        return value
    if type(value) is datetime:
        return ["datetime", value.isoformat()]
    if type(value) is timedelta:
        return ["timedelta", value.days, value.seconds, value.microseconds]
    if type(value) is RdpSessionState:
        return ["rdp-session-state", value.value]
    value_type = type(value)
    record_tag = _TAGS_BY_TYPE.get(value_type)
    if record_tag is not None:
        _schema_type, names = _SCHEMAS[record_tag]
        return [
            "record",
            record_tag,
            [encode_state_value(getattr(value, name)) for name in names],
        ]
    if value_type is random.Random:
        return ["random", encode_random_state(value.getstate())]
    if value_type is list:
        return ["list", [encode_state_value(item) for item in value]]
    if value_type is tuple:
        return ["tuple", [encode_state_value(item) for item in value]]
    if value_type is set:
        return ["set", _sort_encoded([encode_state_value(item) for item in value])]
    if value_type is frozenset:
        return ["frozenset", _sort_encoded([encode_state_value(item) for item in value])]
    if value_type is dict:
        return [
            "dict",
            [[encode_state_value(key), encode_state_value(item)] for key, item in value.items()],
        ]
    raise TypeError(f"StateManager checkpoint value type is unsupported: {value_type.__name__}")


def _tagged(value: object, *, length: int | None = None) -> list[object]:
    if type(value) is not list or not value or type(value[0]) is not str:
        raise CheckpointCorruptionError("StateManager checkpoint value tag is invalid")
    if length is not None and len(value) != length:
        raise CheckpointCorruptionError("StateManager checkpoint value record is invalid")
    return value


def decode_state_value(value: object) -> object:
    """Validate and decode one inert allowlisted StateManager value."""

    if value is None or type(value) in {bool, int, float, str, bytes}:
        return value
    tagged = _tagged(value)
    tag = tagged[0]
    if tag == "datetime":
        _tag, encoded = _tagged(tagged, length=2)
        if type(encoded) is not str:
            raise CheckpointCorruptionError("StateManager checkpoint datetime is invalid")
        try:
            decoded = datetime.fromisoformat(encoded)
        except ValueError as error:
            raise CheckpointCorruptionError(
                "StateManager checkpoint datetime is invalid"
            ) from error
        if decoded.tzinfo is None or decoded.utcoffset() is None:
            raise CheckpointCorruptionError("StateManager checkpoint datetime lacks an offset")
        return decoded
    if tag == "timedelta":
        _tag, days, seconds, microseconds = _tagged(tagged, length=4)
        if (
            type(days) is not int
            or type(seconds) is not int
            or type(microseconds) is not int
            or not 0 <= seconds < 86_400
            or not 0 <= microseconds < 1_000_000
        ):
            raise CheckpointCorruptionError("StateManager checkpoint timedelta is invalid")
        return timedelta(days=days, seconds=seconds, microseconds=microseconds)
    if tag == "rdp-session-state":
        _tag, state = _tagged(tagged, length=2)
        if type(state) is not str:
            raise CheckpointCorruptionError("RDP checkpoint session state is invalid")
        try:
            return RdpSessionState(state)
        except ValueError as error:
            raise CheckpointCorruptionError("RDP checkpoint session state is invalid") from error
    if tag == "record":
        _tag, record_tag, encoded_fields = _tagged(tagged, length=3)
        if type(record_tag) is not str or type(encoded_fields) is not list:
            raise CheckpointCorruptionError("StateManager checkpoint record is invalid")
        if record_tag == "active-session" and len(encoded_fields) == 34:
            record_tag = "active-session-v2"
            encoded_fields = [*encoded_fields, None]
        # Explicit, lossless upgrade of pre-exec process records. Old readers reject
        # the versioned tags; new readers retain legacy scenarios/checkpoint state.
        if record_tag == "running-process" and len(encoded_fields) == 21:
            record_tag = "running-process-v2"
            encoded_fields = [
                *encoded_fields,
                encode_state_value(0),
                encode_state_value(None),
                encode_state_value(()),
                encode_state_value(""),
            ]
        elif record_tag == "process-identity" and len(encoded_fields) == 12:
            record_tag = "process-identity-v2"
            encoded_fields = [
                *encoded_fields,
                encode_state_value(0),
                encode_state_value(None),
                encode_state_value(""),
            ]
        # v3 adds optional explicit credentials. Never infer them from a principal
        # or a restored session: old records did not establish those facts.
        if record_tag == "running-process-v2" and len(encoded_fields) == 25:
            record_tag = "running-process-v3"
            encoded_fields = [*encoded_fields, encode_state_value(None)]
        elif record_tag == "process-identity-v2" and len(encoded_fields) == 15:
            record_tag = "process-identity-v3"
            encoded_fields = [*encoded_fields, encode_state_value(None)]
        # Older snapshots have no native process version; never invent history.
        if record_tag == "running-process-v3" and len(encoded_fields) == 26:
            record_tag = "running-process-v4"
            encoded_fields = [*encoded_fields, encode_state_value(None)]
        elif record_tag == "process-identity-v3" and len(encoded_fields) == 16:
            record_tag = "process-identity-v4"
            encoded_fields = [*encoded_fields, encode_state_value(None)]
        if record_tag == "running-process-v4" and len(encoded_fields) == 27:
            record_tag = "running-process-v5"
            encoded_fields = [*encoded_fields, encode_state_value(None)]
        if record_tag == "running-process-v5" and len(encoded_fields) == 28:
            record_tag = "running-process-v6"
            encoded_fields = [*encoded_fields, encode_state_value(None)]
        if record_tag == "running-process-v6" and len(encoded_fields) == 29:
            record_tag = "running-process-v7"
            encoded_fields = [*encoded_fields, encode_state_value(None)]
        if record_tag == "running-process-v7" and len(encoded_fields) == 30:
            record_tag = "running-process-v8"
            encoded_fields = [*encoded_fields, encode_state_value(None)]
        if record_tag == "running-process-v8" and len(encoded_fields) == 31:
            record_tag = "running-process-v9"
            encoded_fields = [*encoded_fields, None]
        if record_tag == "process-identity-v4" and len(encoded_fields) == 17:
            record_tag = "process-identity-v5"
            encoded_fields = [*encoded_fields, None]
        if record_tag == "running-process-v9" and len(encoded_fields) == 32:
            record_tag = "running-process-v10"
            encoded_fields = [*encoded_fields, None, encode_state_value(())]
        if record_tag == "process-identity-v5" and len(encoded_fields) == 18:
            record_tag = "process-identity-v6"
            encoded_fields = [*encoded_fields, None]
        if record_tag == "running-process-v10" and len(encoded_fields) == 34:
            record_tag = "running-process-v11"
            encoded_fields = [*encoded_fields, None]
        if record_tag == "process-identity-v6" and len(encoded_fields) == 19:
            record_tag = "process-identity-v7"
            encoded_fields = [*encoded_fields, None]
        if record_tag == "running-process-v11" and len(encoded_fields) == 35:
            record_tag = "running-process-v12"
            encoded_fields = [*encoded_fields, None]
        if record_tag == "running-process-v12" and len(encoded_fields) == 36:
            record_tag = "running-process-v13"
            encoded_fields = [*encoded_fields, encode_state_value(())]
        if record_tag == "process-identity-v7" and len(encoded_fields) == 20:
            record_tag = "process-identity-v8"
            encoded_fields = [*encoded_fields, None]
        if record_tag == "running-process-v13" and len(encoded_fields) == 37:
            record_tag = "running-process-v14"
            encoded_fields = [*encoded_fields, None]
        if record_tag == "process-identity-v8" and len(encoded_fields) == 21:
            record_tag = "process-identity-v9"
            encoded_fields = [*encoded_fields, None]
        if record_tag == "running-process-v14" and len(encoded_fields) == 38:
            record_tag = "running-process-v15"
            encoded_fields = [*encoded_fields, None]
        if record_tag == "process-identity-v9" and len(encoded_fields) == 22:
            record_tag = "process-identity-v10"
            encoded_fields = [*encoded_fields, None]
        schema = _SCHEMAS.get(record_tag)
        if schema is None:
            raise CheckpointCorruptionError("StateManager checkpoint record type is unsupported")
        _value_type, names = schema
        if len(encoded_fields) != len(names):
            raise CheckpointCorruptionError("StateManager checkpoint record width changed")
        document = {
            name: decode_state_value(item) for name, item in zip(names, encoded_fields, strict=True)
        }
        try:
            return _ADAPTERS[record_tag].validate_python(document)
        except (TypeError, ValueError, ValidationError) as error:
            raise CheckpointCorruptionError("StateManager checkpoint record is invalid") from error
    if tag == "random":
        _tag, state = _tagged(tagged, length=2)
        rng = random.Random()
        try:
            rng.setstate(decode_random_state(state))
        except (TypeError, ValueError) as error:
            raise CheckpointCorruptionError("StateManager checkpoint RNG is invalid") from error
        return rng
    if tag in {"list", "tuple", "set", "frozenset"}:
        _tag, items = _tagged(tagged, length=2)
        if type(items) is not list:
            raise CheckpointCorruptionError("StateManager checkpoint container is invalid")
        decoded_items = [decode_state_value(item) for item in items]
        if tag == "list":
            return decoded_items
        if tag == "tuple":
            return tuple(decoded_items)
        try:
            return set(decoded_items) if tag == "set" else frozenset(decoded_items)
        except TypeError as error:
            raise CheckpointCorruptionError(
                "StateManager checkpoint set contains an unhashable value"
            ) from error
    if tag == "dict":
        _tag, rows = _tagged(tagged, length=2)
        if type(rows) is not list:
            raise CheckpointCorruptionError("StateManager checkpoint mapping is invalid")
        decoded: dict[object, object] = {}
        for row in rows:
            if type(row) is not list or len(row) != 2:
                raise CheckpointCorruptionError("StateManager checkpoint mapping row is invalid")
            key, item = row
            decoded_key = decode_state_value(key)
            try:
                duplicate = decoded_key in decoded
            except TypeError as error:
                raise CheckpointCorruptionError(
                    "StateManager checkpoint mapping key is unhashable"
                ) from error
            if duplicate:
                raise CheckpointCorruptionError("StateManager checkpoint mapping key is duplicated")
            decoded[decoded_key] = decode_state_value(item)
        return decoded
    raise CheckpointCorruptionError(f"StateManager checkpoint value tag is unsupported: {tag}")


__all__ = ["decode_state_value", "encode_state_value"]
