"""Bounded live head and allocator deltas for ``StateManager``.

The participant names every runtime field it owns. History-growing allocator ledgers are emitted
as immutable last-write-wins records; retained sessions, processes, threads, connections, and
bounded allocator windows remain in the small live head. No arbitrary object graph is accepted.
"""

from __future__ import annotations

from datetime import datetime
from itertools import chain

from evidenceforge.events.identity import (
    MacosProcessAuditBinding,
    MacosProcessPrivilegeDrop,
    MacosProcessServiceDrop,
    validate_process_arguments,
    validate_process_environment,
)
from evidenceforge.events.macos_descriptors import validate_macos_descriptors
from evidenceforge.events.macos_exec_image import validate_macos_exec_image
from evidenceforge.events.macos_exec_script import validate_macos_exec_script
from evidenceforge.events.macos_execution_directory import validate_macos_execution_directory
from evidenceforge.events.macos_policy import MacosPolicyRefusalReceipt
from evidenceforge.events.macos_runtime import validate_macos_image_security
from evidenceforge.events.parentage import ProcessParentageChange, validate_process_parentage
from evidenceforge.events.process_executable import validate_process_executable_version
from evidenceforge.events.process_outcome import PosixProcessExit
from evidenceforge.generation.indexes import (
    ExpiringIndex,
    GroupedTemporalIndex,
    TemporalAllocationIndex,
)
from evidenceforge.generation.macos_process_census import MacosProcessCensus
from evidenceforge.generation.macos_terminal_devices import (
    validate_native_pipe_state,
    validate_terminal_state,
)
from evidenceforge.generation.state_manager import (
    _MAX_RETAINED_PROCESS_DESCRIPTOR_TABLES,
    _MAX_RETAINED_PROCESS_DIRECTORIES,
    StateManager,
)
from evidenceforge.utils.rng import stable_uuid

from .errors import CheckpointCorruptionError
from .owner_inventory import STATE_MANAGER_CHECKPOINT_FIELDS, assert_transient_owner_state_empty
from .packed import dumps, loads
from .participants import ParticipantSeal
from .state_values import decode_state_value, encode_state_value
from .store import HeadDraft, SegmentDraft

_SCHEMA_VERSION = "11"
_LEGACY_VERSION = "6"
_JOB_CONTROL_FIELDS = {"_posix_job_control_reservations", "_posix_job_control_reservation_counts"}
_TERMINAL_FIELDS = {
    "_macos_terminal_sessions",
    "_macos_terminal_slots",
    "_macos_terminal_ordinals",
    "_macos_pipe_counters",
}

_INCREMENTAL_FIELDS = frozenset(
    {
        "_linux_logind_session_used_ids",
        "_logon_id_second_ordinals",
        "_semantic_peer_ordinals",
        "_used_logon_ids",
    }
)
_STORE_FIELDS = (
    "_active_sessions",
    "_open_connections",
    "_running_processes",
    "_running_threads",
)
_GROUPED_TEMPORAL_FIELDS = (
    "_authoritative_session_ends",
    "_ended_sessions_by_system_end",
    "_ended_sessions_by_username_end",
)
_TEMPORAL_ALLOCATION_FIELDS = (
    "_linux_logind_session_allocations",
    "_linux_pid_allocations",
)
_EXPIRING_FIELDS = (
    "_macos_policy_refusals",
    "_ended_sessions",
    "_ended_threads",
)
_PROCESS_REFERENCE_FIELDS = frozenset(
    {
        "_ended_processes_by_key",
        "_ended_processes_by_object_id",
        "_process_object_ids",
        "_processes_by_object_id",
    }
)
_DERIVED_CONNECTION_FIELDS = frozenset(
    {
        "_terminal_connection_ids",
    }
)
_SPECIAL_FIELDS = frozenset(
    {
        "state",
        *_STORE_FIELDS,
        *_GROUPED_TEMPORAL_FIELDS,
        *_TEMPORAL_ALLOCATION_FIELDS,
        *_EXPIRING_FIELDS,
        *_PROCESS_REFERENCE_FIELDS,
        *_DERIVED_CONNECTION_FIELDS,
    }
)
_LIVE_FIELDS = frozenset(
    field.name
    for field in STATE_MANAGER_CHECKPOINT_FIELDS
    if field.disposition == "bounded-live-head"
)
_SIMPLE_FIELDS = tuple(sorted(_LIVE_FIELDS - _SPECIAL_FIELDS))

if _SPECIAL_FIELDS - _LIVE_FIELDS:
    raise RuntimeError("StateManager checkpoint special fields are not classified as live state")
if (_LIVE_FIELDS - _SPECIAL_FIELDS) != frozenset(_SIMPLE_FIELDS):
    raise RuntimeError("StateManager checkpoint live field routing is incomplete")
if _INCREMENTAL_FIELDS != frozenset(
    field.name
    for field in STATE_MANAGER_CHECKPOINT_FIELDS
    if field.disposition == "immutable-incremental-segments"
):
    raise RuntimeError("StateManager checkpoint incremental field routing is incomplete")


def _encoded_items(mapping: object) -> object:
    return encode_state_value(
        [[key, value] for key, value in mapping.items()]  # type: ignore[union-attr]
    )


def _decode_items(value: object, label: str) -> list[tuple[object, object]]:
    decoded = decode_state_value(value)
    if type(decoded) is not list:
        raise CheckpointCorruptionError(f"StateManager checkpoint {label} table is invalid")
    rows: list[tuple[object, object]] = []
    for row in decoded:
        if type(row) not in {list, tuple} or len(row) != 2:
            raise CheckpointCorruptionError(f"StateManager checkpoint {label} row is invalid")
        rows.append((row[0], row[1]))
    return rows


def _capture_expiring(index: ExpiringIndex[object, object]) -> object:
    keys = sorted(index._items, key=index._orders.__getitem__)
    return encode_state_value(
        [[key, index._items[key], index._deadlines[key], key in index._protected] for key in keys]
    )


def _restore_expiring(
    index: ExpiringIndex[object, object],
    encoded: object,
    label: str,
) -> None:
    decoded = decode_state_value(encoded)
    if type(decoded) is not list:
        raise CheckpointCorruptionError(f"StateManager checkpoint {label} table is invalid")
    for row in decoded:
        if type(row) is not list or len(row) != 4:
            raise CheckpointCorruptionError(f"StateManager checkpoint {label} row is invalid")
        key, value, deadline, protected = row
        if type(deadline) not in {int, float} or type(protected) is not bool:
            raise CheckpointCorruptionError(f"StateManager checkpoint {label} row is invalid")
        try:
            index.set(key, value, float(deadline))
            if protected:
                index.protect(key)
        except (KeyError, TypeError, ValueError) as error:
            raise CheckpointCorruptionError(
                f"StateManager checkpoint {label} row is invalid"
            ) from error


def _capture_grouped(index: GroupedTemporalIndex[object, object]) -> object:
    current = sorted(index._current.items(), key=lambda item: item[1][2])
    return encode_state_value(
        [[key, group, event_time] for key, (group, event_time, _sequence, _version) in current]
    )


def _restore_grouped(
    index: GroupedTemporalIndex[object, object],
    encoded: object,
    label: str,
) -> None:
    decoded = decode_state_value(encoded)
    if type(decoded) is not list:
        raise CheckpointCorruptionError(f"StateManager checkpoint {label} table is invalid")
    for row in decoded:
        if type(row) is not list or len(row) != 3 or type(row[2]) is not datetime:
            raise CheckpointCorruptionError(f"StateManager checkpoint {label} row is invalid")
        key, group, event_time = row
        try:
            index.add(key, group, event_time)
        except (TypeError, ValueError) as error:
            raise CheckpointCorruptionError(
                f"StateManager checkpoint {label} row is invalid"
            ) from error


def _capture_temporal(index: TemporalAllocationIndex) -> object:
    records = sorted(
        (record for block in index._blocks for record in block),
        key=lambda record: record[1],
    )
    return encode_state_value([[event_time, value] for event_time, _sequence, value in records])


def _restore_temporal(encoded: object, label: str) -> TemporalAllocationIndex:
    decoded = decode_state_value(encoded)
    if type(decoded) is not list:
        raise CheckpointCorruptionError(f"StateManager checkpoint {label} table is invalid")
    index = TemporalAllocationIndex()
    for row in decoded:
        if (
            type(row) is not list
            or len(row) != 2
            or type(row[0]) is not datetime
            or type(row[1]) is not int
        ):
            raise CheckpointCorruptionError(f"StateManager checkpoint {label} row is invalid")
        index.add(row[0], row[1])
    return index


def _capture_process_indexes(manager: StateManager) -> dict[str, object]:
    by_object = _capture_expiring(manager._ended_processes_by_object_id)  # type: ignore[arg-type]
    key_rows: list[list[object]] = []
    for key in sorted(
        manager._ended_processes_by_key._items,
        key=manager._ended_processes_by_key._orders.__getitem__,
    ):
        process = manager._ended_processes_by_key._items[key]
        key_rows.append(
            [
                key,
                process.ecar_object_id,
                manager._ended_processes_by_key._deadlines[key],
                key in manager._ended_processes_by_key._protected,
            ]
        )
    return {
        "active_object_ids": encode_state_value(manager._process_object_ids),
        "active_object_keys": encode_state_value(list(manager._processes_by_object_id)),
        "ended_by_key": encode_state_value(key_rows),
        "ended_by_object": by_object,
    }


def _restore_process_indexes(manager: StateManager, document: object) -> None:
    if type(document) is not dict or set(document) != {
        "active_object_ids",
        "active_object_keys",
        "ended_by_key",
        "ended_by_object",
    }:
        raise CheckpointCorruptionError("StateManager checkpoint process indexes are invalid")
    _restore_expiring(
        manager._ended_processes_by_object_id,  # type: ignore[arg-type]
        document["ended_by_object"],
        "ended process object",
    )
    ended_by_object = manager._ended_processes_by_object_id._items
    decoded_key_rows = decode_state_value(document["ended_by_key"])
    if type(decoded_key_rows) is not list:
        raise CheckpointCorruptionError(
            "StateManager checkpoint ended process key table is invalid"
        )
    for row in decoded_key_rows:
        if type(row) is not list or len(row) != 4:
            raise CheckpointCorruptionError(
                "StateManager checkpoint ended process key row is invalid"
            )
        key, object_id, deadline, protected = row
        if (
            type(key) is not tuple
            or len(key) != 2
            or type(object_id) is not str
            or type(deadline) not in {int, float}
            or type(protected) is not bool
        ):
            raise CheckpointCorruptionError(
                "StateManager checkpoint ended process key row is invalid"
            )
        process = ended_by_object.get(object_id)
        if process is None:
            raise CheckpointCorruptionError(
                "StateManager checkpoint ended process reference is missing"
            )
        manager._ended_processes_by_key.set(key, process, float(deadline))
        if protected:
            manager._ended_processes_by_key.protect(key)

    manager._process_object_ids = {
        (process.system, process.pid): process.ecar_object_id
        for process in manager._running_processes.values()
    }
    expected_object_ids = decode_state_value(document["active_object_ids"])
    if expected_object_ids != manager._process_object_ids:
        raise CheckpointCorruptionError("StateManager checkpoint active process IDs disagree")
    manager._processes_by_object_id = {
        process.ecar_object_id: process for process in manager._running_processes.values()
    }
    expected_object_keys = decode_state_value(document["active_object_keys"])
    if type(expected_object_keys) is not list or expected_object_keys != list(
        manager._processes_by_object_id
    ):
        raise CheckpointCorruptionError("StateManager checkpoint process object routes disagree")


def _capture_head(manager: StateManager) -> bytes:
    with manager._lock:
        assert_transient_owner_state_empty(
            manager,
            STATE_MANAGER_CHECKPOINT_FIELDS,
            owner_name="state-manager",
        )
        stores = {name: _encoded_items(getattr(manager, name)) for name in _STORE_FIELDS}
        expiring = {name: _capture_expiring(getattr(manager, name)) for name in _EXPIRING_FIELDS}
        grouped = {
            name: _capture_grouped(getattr(manager, name)) for name in _GROUPED_TEMPORAL_FIELDS
        }
        temporal = {
            name: encode_state_value(
                [[key, _capture_temporal(index)] for key, index in getattr(manager, name).items()]
            )
            for name in _TEMPORAL_ALLOCATION_FIELDS
        }
        return dumps(
            {
                "expiring": expiring,
                "grouped": grouped,
                "process_indexes": _capture_process_indexes(manager),
                "schema_version": _SCHEMA_VERSION,
                "simple": {
                    name: encode_state_value(getattr(manager, name)) for name in _SIMPLE_FIELDS
                },
                "state": {
                    "current_time": encode_state_value(manager.state.current_time),
                    "dns_cache": encode_state_value(manager.state.dns_cache),
                },
                "stores": stores,
                "temporal": temporal,
            }
        )


def _restore_head(manager: StateManager, head: bytes) -> None:
    document = loads(head)
    if type(document) is not dict or document.get("schema_version") not in {
        _SCHEMA_VERSION,
        _LEGACY_VERSION,
        "7",
        "8",
        "9",
        "10",
    }:
        raise CheckpointCorruptionError("StateManager checkpoint head schema is invalid")
    if set(document) != {
        "expiring",
        "grouped",
        "process_indexes",
        "schema_version",
        "simple",
        "state",
        "stores",
        "temporal",
    }:
        raise CheckpointCorruptionError("StateManager checkpoint head fields changed")
    fresh = StateManager()
    simple = document["simple"]
    legacy = document["schema_version"] == _LEGACY_VERSION
    missing = _TERMINAL_FIELDS if document["schema_version"] in {"6", "7"} else set()
    if document["schema_version"] != _SCHEMA_VERSION:
        missing = missing | {"_macos_process_census"}
    if legacy:
        missing = missing | _JOB_CONTROL_FIELDS
    if missing:
        if type(simple) is not dict or set(simple) != set(_SIMPLE_FIELDS) - missing:
            raise CheckpointCorruptionError("Legacy StateManager fields changed")
        simple = {**simple, **{name: encode_state_value({}) for name in missing}}
    if type(simple) is not dict or set(simple) != set(_SIMPLE_FIELDS):
        raise CheckpointCorruptionError("StateManager checkpoint simple fields changed")
    for name in _SIMPLE_FIELDS:
        decoded = decode_state_value(simple[name])
        default = getattr(fresh, name)
        if default is None:
            if decoded is not None and type(decoded) is not datetime:
                raise CheckpointCorruptionError(
                    f"StateManager checkpoint field {name} has an invalid type"
                )
        elif type(decoded) is not type(default):
            raise CheckpointCorruptionError(
                f"StateManager checkpoint field {name} has an invalid type"
            )
        setattr(fresh, name, decoded)

    for host, census in fresh._macos_process_census.items():
        if (
            type(host) is not str
            or not host
            or type(census) is not MacosProcessCensus
            or fresh._pid_os.get(host, "macos") != "macos"
        ):
            raise CheckpointCorruptionError("StateManager Mac process census is invalid")

    state = document["state"]
    if type(state) is not dict or set(state) != {"current_time", "dns_cache"}:
        raise CheckpointCorruptionError("StateManager checkpoint GeneratorState is invalid")
    current_time = decode_state_value(state["current_time"])
    dns_cache = decode_state_value(state["dns_cache"])
    if (current_time is not None and type(current_time) is not datetime) or type(
        dns_cache
    ) is not dict:
        raise CheckpointCorruptionError("StateManager checkpoint GeneratorState is invalid")
    fresh.state.current_time = current_time
    fresh.state.dns_cache = dns_cache  # type: ignore[assignment]

    stores = document["stores"]
    if type(stores) is not dict or set(stores) != set(_STORE_FIELDS):
        raise CheckpointCorruptionError("StateManager checkpoint entity stores changed")
    for name in _STORE_FIELDS:
        store = getattr(fresh, name)
        for key, value in _decode_items(stores[name], name):
            try:
                store[key] = value
            except (KeyError, TypeError, ValueError) as error:
                raise CheckpointCorruptionError(
                    f"StateManager checkpoint entity store {name} is invalid"
                ) from error

    for connection in fresh._open_connections.values():
        fresh._refresh_connection_lifecycle(connection)

    expiring = document["expiring"]
    if document["schema_version"] not in {"10", _SCHEMA_VERSION}:
        if type(expiring) is not dict or set(expiring) != set(_EXPIRING_FIELDS) - {
            "_macos_policy_refusals"
        }:
            raise CheckpointCorruptionError("Legacy StateManager expiry tables changed")
        expiring = {
            **expiring,
            "_macos_policy_refusals": _capture_expiring(fresh._macos_policy_refusals),
        }
    if type(expiring) is not dict or set(expiring) != set(_EXPIRING_FIELDS):
        raise CheckpointCorruptionError("StateManager checkpoint expiry tables changed")
    for name in _EXPIRING_FIELDS:
        _restore_expiring(getattr(fresh, name), expiring[name], name)
    for key, receipt in fresh._macos_policy_refusals.items():
        if type(receipt) is not MacosPolicyRefusalReceipt:
            raise CheckpointCorruptionError("StateManager policy-refusal receipt is invalid")
        target = receipt.target
        boot = fresh.get_boot_time(target.hostname)
        if (
            key != target.object_id
            or fresh._pid_os.get(target.hostname) != "macos"
            or boot is None
            or target.refused_at < boot
            or receipt.kernel_thread_id >= fresh._thread_id_counters.get(target.hostname, 0)
            or target.object_id
            != stable_uuid(
                "macos-policy-attempt",
                target.hostname,
                target.refused_at.isoformat(),
                target.allocation_position,
                target.image,
                receipt.initiator_object_id,
            )
        ):
            raise CheckpointCorruptionError("StateManager policy-refusal allocation is invalid")

    grouped = document["grouped"]
    if type(grouped) is not dict or set(grouped) != set(_GROUPED_TEMPORAL_FIELDS):
        raise CheckpointCorruptionError("StateManager checkpoint temporal groups changed")
    for name in _GROUPED_TEMPORAL_FIELDS:
        _restore_grouped(getattr(fresh, name), grouped[name], name)

    temporal = document["temporal"]
    if type(temporal) is not dict or set(temporal) != set(_TEMPORAL_ALLOCATION_FIELDS):
        raise CheckpointCorruptionError("StateManager checkpoint allocation indexes changed")
    for name in _TEMPORAL_ALLOCATION_FIELDS:
        indexes: dict[object, TemporalAllocationIndex] = {}
        for key, encoded in _decode_items(temporal[name], name):
            indexes[key] = _restore_temporal(encoded, name)
        setattr(fresh, name, indexes)

    _restore_process_indexes(fresh, document["process_indexes"])
    from evidenceforge.generation.posix_job_control import validate_restored_job_control
    from evidenceforge.generation.process_responsibility import validate_restored_responsibility

    try:
        validate_restored_responsibility(
            tuple(
                chain(
                    fresh._processes_by_object_id.values(),
                    fresh._ended_processes_by_object_id.values(),
                )
            ),
            fresh._pid_os,
        )
    except (ValueError, TypeError) as error:
        raise CheckpointCorruptionError("StateManager responsibility state is invalid") from error

    try:
        validate_restored_job_control(
            fresh._posix_job_control_reservations,
            fresh._posix_job_control_reservation_counts,
            tuple(
                chain(
                    fresh._processes_by_object_id.values(),
                    fresh._ended_processes_by_object_id.values(),
                )
            ),
            fresh._pid_os,
            legacy=legacy,
        )
    except (ValueError, TypeError) as error:
        raise CheckpointCorruptionError("StateManager POSIX membership state is invalid") from error
    try:
        validate_terminal_state(
            fresh._macos_terminal_sessions,
            fresh._macos_terminal_slots,
            fresh._macos_terminal_ordinals,
            fresh._posix_job_control_reservations,
            fresh._pid_os,
        )
        validate_native_pipe_state(
            fresh._macos_pipe_counters,
            tuple(
                chain(
                    fresh._processes_by_object_id.values(),
                    fresh._ended_processes_by_object_id.values(),
                )
            ),
            fresh._pid_os,
            command_streams=tuple(
                session.ssh_command_streams
                for session in chain(
                    fresh._active_sessions.values(),
                    (row[0] for row in fresh._ended_sessions.values()),
                )
                if session.ssh_command_streams is not None
            ),
        )
        if document["schema_version"] in {"6", "7"} and any(
            table.native_last_fd is not None
            or any(binding.native_pipe_id is not None for binding in table.bindings)
            for process in chain(
                fresh._processes_by_object_id.values(), fresh._ended_processes_by_object_id.values()
            )
            for table in process.descriptor_history
        ):
            raise ValueError("Older state head cannot claim native descriptor production")
    except (ValueError, TypeError) as error:
        raise CheckpointCorruptionError("StateManager Mac terminal state is invalid") from error
    for host, value in fresh._macos_audit_session_counters.items():
        if (
            type(host) is not str
            or fresh._pid_os.get(host) != "macos"
            or type(value) is not int
            or not 100_000 <= value < 2**32 - 1
        ):
            raise CheckpointCorruptionError("StateManager macOS audit session counter is invalid")
    audit_owners: set[tuple[str, int]] = set()
    for session in chain(
        fresh._active_sessions.values(), (row[0] for row in fresh._ended_sessions.values())
    ):
        origin = session.audit_origin
        ssh = session.session_kind == "ssh" and session.auth_protocol == "ssh"
        gui = (
            session.session_kind == "interactive"
            and type(session.logon_type) is int
            and session.logon_type == 2
            and session.auth_protocol == "local"
            and session.source_ip == "-"
            and type(session.source_port) is int
            and session.source_port == 0
            and session.transport_pid is None
            and session.network_close_time is None
            and origin is not None
            and type(session.effective_uid) is int
            and session.effective_uid == origin.audit_uid
            and type(session.session_id) is int
            and session.session_id == 0
        )
        if origin is not None and (
            not (ssh or gui)
            or origin.audit_session_id > fresh._macos_audit_session_counters.get(session.system, 0)
            or origin.created_at < session.start_time
            or (
                session.source_ready_time is not None
                and origin.created_at > session.source_ready_time
            )
            or (
                session.network_close_time is not None
                and origin.created_at >= session.network_close_time
            )
        ):
            raise CheckpointCorruptionError("StateManager native session audit origin is invalid")
        if origin is not None:
            key = session.system, origin.audit_session_id
            if key in audit_owners:
                raise CheckpointCorruptionError("StateManager session audit origin is duplicated")
            audit_owners.add(key)
        streams = session.ssh_command_streams
        if streams is not None:
            if (
                document["schema_version"] not in {"9", "10", _SCHEMA_VERSION}
                or not ssh
                or origin is None
                or session.effective_uid != origin.audit_uid
                or streams.hostname != session.system
                or streams.session_object_id != session.ecar_object_id
                or session.source_ready_time is None
                or streams.available_at > session.source_ready_time
                or streams.available_at < origin.created_at
                or (
                    session.network_close_time is not None
                    and streams.available_at >= session.network_close_time
                )
            ):
                raise CheckpointCorruptionError("StateManager SSH command stream owner is invalid")
    for host, version in fresh._macos_audit_pid_versions.items():
        if (
            type(host) is not str
            or fresh._pid_os.get(host) != "macos"
            or type(version) is not int
            or not 0 < version < 2**32
        ):
            raise CheckpointCorruptionError("StateManager macOS audit PID counter is invalid")
    for process in chain(
        fresh._processes_by_object_id.values(), fresh._ended_processes_by_object_id.values()
    ):
        try:
            history = process.descriptor_history
            if type(history) is not tuple or len(history) > _MAX_RETAINED_PROCESS_DESCRIPTOR_TABLES:
                raise ValueError("Invalid descriptor history container")
            previous = None
            object_kinds: dict[str, str] = {}
            frontier = max(
                process.last_activity_time or process.start_time,
                process.executed_at or process.start_time,
            )
            for table in history:
                validate_macos_descriptors(
                    table,
                    hostname=process.system,
                    observed_at=table.observed_at,
                    platform=fresh._pid_os.get(process.system, "unknown"),
                )
                if (
                    table.observed_at < process.start_time
                    or table.observed_at > frontier
                    or (process.end_time is not None and table.observed_at > process.end_time)
                    or (previous is not None and table.observed_at <= previous)
                ):
                    raise ValueError("Invalid descriptor history ordering")
                for binding in table.bindings:
                    previous_kind = object_kinds.setdefault(binding.object_id, binding.kind)
                    if previous_kind != binding.kind:
                        raise ValueError("Conflicting descriptor object kinds in retained history")
                previous = table.observed_at
        except (AttributeError, TypeError, ValueError) as error:
            raise CheckpointCorruptionError("StateManager descriptor history is invalid") from error
        try:
            history = process.directory_history
            if type(history) is not tuple or len(history) > _MAX_RETAINED_PROCESS_DIRECTORIES:
                raise ValueError("Invalid directory history container")
            previous = None
            frontier = max(
                process.last_activity_time or process.start_time,
                process.executed_at or process.start_time,
            )
            for directory in history:
                validate_macos_execution_directory(
                    directory,
                    hostname=process.system,
                    observed_at=directory.observed_at,
                    platform=fresh._pid_os.get(process.system, "unknown"),
                )
                if (
                    directory.observed_at < process.start_time
                    or directory.observed_at > frontier
                    or (process.end_time is not None and directory.observed_at > process.end_time)
                    or (previous is not None and directory.observed_at <= previous)
                ):
                    raise ValueError("Invalid directory history ordering")
                previous = directory.observed_at
        except (AttributeError, TypeError, ValueError) as error:
            raise CheckpointCorruptionError("StateManager directory history is invalid") from error
        try:
            for directory, observed_at in (
                (process.execution_directory, process.executed_at or process.start_time),
                *(
                    (identity.execution_directory, identity.execution_started_at)
                    for identity in process.prior_executions
                ),
            ):
                validate_macos_execution_directory(
                    directory,
                    hostname=process.system,
                    observed_at=observed_at,
                    platform=fresh._pid_os.get(process.system, "unknown"),
                )
        except ValueError as error:
            raise CheckpointCorruptionError(
                "StateManager execution directory is invalid"
            ) from error
        try:
            for version in (
                process.executable_version,
                *(identity.executable_version for identity in process.prior_executions),
            ):
                validate_process_executable_version(
                    version, fresh._pid_os.get(process.system, "unknown")
                )
        except ValueError as error:
            raise CheckpointCorruptionError("StateManager executable version is invalid") from error
        try:
            for script in (
                process.exec_script,
                *(item.exec_script for item in process.prior_executions),
            ):
                validate_macos_exec_script(
                    script,
                    platform=fresh._pid_os.get(process.system, "unknown"),
                    hostname=process.system,
                )
        except ValueError as error:
            raise CheckpointCorruptionError("StateManager script execution is invalid") from error
        try:
            for image in (
                process.exec_image,
                *(item.exec_image for item in process.prior_executions),
            ):
                validate_macos_exec_image(image, fresh._pid_os.get(process.system, "unknown"))
        except ValueError as error:
            raise CheckpointCorruptionError("StateManager execution image is invalid") from error
        try:
            for security in (
                process.image_security,
                *(identity.image_security for identity in process.prior_executions),
            ):
                validate_macos_image_security(
                    security, fresh._pid_os.get(process.system, "unknown")
                )
        except ValueError as error:
            raise CheckpointCorruptionError("StateManager image security is invalid") from error
        try:
            validate_process_arguments(process.arguments, command_line=process.command_line)
        except ValueError as error:
            raise CheckpointCorruptionError("StateManager process argv is invalid") from error
        if process.arguments is not None and fresh._pid_os.get(process.system) not in {
            "macos",
            "linux",
        }:
            raise CheckpointCorruptionError("StateManager process argv requires a POSIX host")
        try:
            validate_process_environment(process.environment)
        except ValueError as error:
            raise CheckpointCorruptionError(
                "StateManager process environment is invalid"
            ) from error
        if process.environment is not None and fresh._pid_os.get(process.system) not in {
            "macos",
            "linux",
        }:
            raise CheckpointCorruptionError(
                "StateManager process environment requires a POSIX host"
            )
        try:
            validate_process_parentage(
                process.parentage,
                hostname=process.system,
                object_id=process.ecar_object_id,
                parent_pid=process.parent_pid,
                started_at=process.start_time,
            )
        except ValueError as error:
            raise CheckpointCorruptionError("StateManager process parentage is invalid") from error
        if process.parentage is not None and fresh._pid_os.get(process.system) not in {
            "macos",
            "linux",
        }:
            raise CheckpointCorruptionError("StateManager process parentage requires a POSIX host")
        if type(process.parentage_history) is not tuple or len(process.parentage_history) > 64:
            raise CheckpointCorruptionError("StateManager parent history is invalid")
        prior_parent_change = None
        for change in process.parentage_history:
            if (
                type(change) is not ProcessParentageChange
                or change.changed_at < process.start_time
                or (process.end_time is not None and change.changed_at > process.end_time)
                or (
                    prior_parent_change is not None
                    and (
                        prior_parent_change.after != change.before
                        or prior_parent_change.changed_at >= change.changed_at
                    )
                )
            ):
                raise CheckpointCorruptionError("StateManager parent history is inconsistent")
            prior_parent_change = change
        if prior_parent_change is not None and prior_parent_change.after != process.parentage:
            raise CheckpointCorruptionError("StateManager parent history lost its current frontier")
        outcome = process.exit_outcome
        if outcome is not None and (
            type(outcome) is not PosixProcessExit
            or process.end_time is None
            or fresh._pid_os.get(process.system) not in {"macos", "linux"}
            or (
                fresh._pid_os.get(process.system) == "macos"
                and outcome.signal is not None
                and outcome.signal >= 32
            )
        ):
            raise CheckpointCorruptionError("StateManager process exit outcome is invalid")
        binding = process.audit_binding
        if binding is not None and (
            type(binding) is not MacosProcessAuditBinding
            or fresh._pid_os.get(process.system) != "macos"
            or binding.origin.audit_session_id
            > fresh._macos_audit_session_counters.get(process.system, 0)
            or binding.bound_at < process.start_time
            or binding.bound_at > (process.last_activity_time or process.start_time)
            or (process.end_time is not None and binding.bound_at >= process.end_time)
            or process.credentials is None
            or process.credentials.audit_uid != binding.origin.audit_uid
            or process.credentials.audit_session_id != binding.origin.audit_session_id
        ):
            raise CheckpointCorruptionError("StateManager process audit-origin binding is invalid")
        drop = process.privilege_drop
        if drop is not None and (
            type(drop) is not MacosProcessPrivilegeDrop
            or fresh._pid_os.get(process.system) != "macos"
            or drop.origin.audit_session_id
            > fresh._macos_audit_session_counters.get(process.system, 0)
            or drop.dropped_at <= process.start_time
            or drop.dropped_at > (process.last_activity_time or process.start_time)
            or (process.end_time is not None and drop.dropped_at >= process.end_time)
            or process.credentials is None
            or process.credentials.origin != drop.after.origin
            or process.username != drop.after_principal
            or process.integrity_level != drop.after_integrity
            or process.audit_binding is not None
        ):
            raise CheckpointCorruptionError("StateManager SSH privilege-drop history is invalid")
        service_drop = process.service_drop
        if service_drop is not None and (
            type(service_drop) is not MacosProcessServiceDrop
            or fresh._pid_os.get(process.system) != "macos"
            or service_drop.execution_ordinal > process.execution_ordinal
            or service_drop.dropped_at <= process.start_time
            or service_drop.dropped_at > (process.last_activity_time or process.start_time)
            or (process.end_time is not None and service_drop.dropped_at >= process.end_time)
            or process.credentials is None
            or (
                process.credentials.origin != service_drop.after.origin
                if service_drop.gui_session is None
                else (
                    process.logon_id != service_drop.after_logon_id
                    or (
                        process.credentials.real_uid,
                        process.credentials.effective_uid,
                        process.credentials.real_gid,
                        process.credentials.effective_gid,
                    )
                    != (
                        service_drop.after.real_uid,
                        service_drop.after.effective_uid,
                        service_drop.after.real_gid,
                        service_drop.after.effective_gid,
                    )
                    or (process.credentials.audit_uid, process.credentials.audit_session_id)
                    != (
                        (service_drop.after.audit_uid, service_drop.after.audit_session_id)
                        if process.execution_ordinal == service_drop.execution_ordinal
                        else (
                            service_drop.gui_audit_origin.audit_uid,
                            service_drop.gui_audit_origin.audit_session_id,
                        )
                    )
                )
            )
            or process.username != service_drop.after_principal
            or process.integrity_level != service_drop.after_integrity
            or process.audit_binding is not None
            or process.privilege_drop is not None
        ):
            raise CheckpointCorruptionError(
                "StateManager service privilege-drop history is invalid"
            )
        versions = (
            process.audit_pid_version,
            *(identity.audit_pid_version for identity in process.prior_executions),
        )
        for version in versions:
            if version is not None and (
                type(version) is not int
                or not 0 < version <= fresh._macos_audit_pid_versions.get(process.system, 0)
            ):
                raise CheckpointCorruptionError("StateManager process audit PID version is invalid")
    fresh.state.active_sessions = fresh._active_sessions
    fresh.state.running_processes = fresh._running_processes
    fresh.state.running_threads = fresh._running_threads
    fresh.state.open_connections = fresh._open_connections
    manager.__dict__.clear()
    manager.__dict__.update(fresh.__dict__)


def _initial_incremental_records(manager: StateManager) -> list[tuple[str, object, object]]:
    records: list[tuple[str, object, object]] = []
    records.extend(
        ("_logon_id_second_ordinals", key, value)
        for key, value in manager._logon_id_second_ordinals.items()
    )
    records.extend(
        ("_semantic_peer_ordinals", key, value)
        for key, value in manager._semantic_peer_ordinals.items()
    )
    records.extend(("_used_logon_ids", key, None) for key in sorted(manager._used_logon_ids))
    records.extend(
        ("_linux_logind_session_used_ids", (system, session_id), None)
        for system, used_ids in manager._linux_logind_session_used_ids.items()
        for session_id in sorted(used_ids)
    )
    return records


def _apply_incremental_record(
    manager: StateManager,
    field_name: object,
    key: object,
    value: object,
) -> None:
    if field_name == "_used_logon_ids":
        if type(key) is not int or value is not None:
            raise CheckpointCorruptionError("StateManager used-LogonID delta is invalid")
        manager._used_logon_ids.add(key)
        return
    if field_name == "_linux_logind_session_used_ids":
        if (
            type(key) is not tuple
            or len(key) != 2
            or type(key[0]) is not str
            or type(key[1]) is not int
            or value is not None
        ):
            raise CheckpointCorruptionError("StateManager logind-ID delta is invalid")
        manager._linux_logind_session_used_ids.setdefault(key[0], set()).add(key[1])
        return
    if field_name == "_logon_id_second_ordinals":
        if (
            type(key) is not tuple
            or len(key) != 3
            or type(key[0]) is not str
            or type(key[1]) is not int
            or type(key[2]) is not int
            or type(value) is not int
        ):
            raise CheckpointCorruptionError("StateManager LogonID ordinal delta is invalid")
        manager._logon_id_second_ordinals[key] = value
        return
    if field_name == "_semantic_peer_ordinals":
        if (
            type(key) is not tuple
            or len(key) != 2
            or any(type(item) is not str for item in key)
            or type(value) is not int
        ):
            raise CheckpointCorruptionError("StateManager semantic ordinal delta is invalid")
        manager._semantic_peer_ordinals[key] = value
        return
    raise CheckpointCorruptionError("StateManager checkpoint delta names an unknown field")


class StateManagerParticipant:
    """Persist bounded StateManager authority and append-only allocator deltas."""

    checkpoint_owner = "state-manager"
    checkpoint_restore_priority = 10
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_compatible_head_versions = (_LEGACY_VERSION, "7", "8")
    checkpoint_compatible_segment_versions = (_LEGACY_VERSION, "7", "8")
    checkpoint_state_fields = STATE_MANAGER_CHECKPOINT_FIELDS

    def __init__(self, manager: StateManager) -> None:
        self.manager = manager
        self._pending_records: list[tuple[str, object, object]] = []
        self._prepared_sequence: int | None = None
        self._prepared_record_count = 0
        self._prepared_seal: ParticipantSeal | None = None
        with manager._lock:
            if manager._checkpoint_incremental_recorder is not None:
                raise RuntimeError("StateManager already has an incremental checkpoint owner")
            self._pending_records.extend(_initial_incremental_records(manager))
            manager._checkpoint_incremental_recorder = self._record_incremental_value

    def _record_incremental_value(self, field_name: str, key: object, value: object) -> None:
        if field_name not in _INCREMENTAL_FIELDS:
            raise RuntimeError(f"StateManager offered unknown checkpoint delta {field_name!r}")
        self._pending_records.append((field_name, key, value))

    @staticmethod
    def _seal_records(records: list[tuple[str, object, object]]) -> tuple[SegmentDraft, ...]:
        latest: dict[tuple[str, object], object] = {}
        try:
            for field_name, key, value in records:
                latest[(field_name, key)] = value
        except TypeError as error:
            raise RuntimeError("StateManager checkpoint delta key is not hashable") from error
        if not latest:
            return ()
        rows = [
            [field_name, encode_state_value(key), encode_state_value(value)]
            for (field_name, key), value in latest.items()
        ]
        return (
            SegmentDraft(
                owner=StateManagerParticipant.checkpoint_owner,
                schema_version=_SCHEMA_VERSION,
                payload=dumps({"records": rows, "schema_version": _SCHEMA_VERSION}),
                record_count=len(rows),
            ),
        )

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Freeze the bounded live head and only allocator changes since the prior commit."""

        if self._prepared_sequence is not None:
            if self._prepared_sequence != sequence or self._prepared_seal is None:
                raise RuntimeError("StateManager participant already prepared another sequence")
            return self._prepared_seal
        with self.manager._lock:
            self._prepared_record_count = len(self._pending_records)
            segments = self._seal_records(self._pending_records[: self._prepared_record_count])
            seal = ParticipantSeal(
                head=HeadDraft(
                    owner=self.checkpoint_owner,
                    schema_version=self.checkpoint_schema_version,
                    payload=_capture_head(self.manager),
                ),
                segments=segments,
            )
        self._prepared_sequence = sequence
        self._prepared_seal = seal
        return seal

    def checkpoint_committed(self, sequence: int) -> None:
        """Advance the allocator journal only after durable publication."""

        if self._prepared_sequence != sequence:
            raise RuntimeError("StateManager commit does not match its prepared sequence")
        del self._pending_records[: self._prepared_record_count]
        self._prepared_sequence = None
        self._prepared_record_count = 0
        self._prepared_seal = None

    def checkpoint_aborted(self, sequence: int) -> None:
        """Retain every allocator mutation after failed publication."""

        if self._prepared_sequence != sequence:
            raise RuntimeError("StateManager abort does not match its prepared sequence")
        self._prepared_sequence = None
        self._prepared_record_count = 0
        self._prepared_seal = None

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Hydrate bounded authority, apply allocator deltas, and attach a fresh recorder."""

        _restore_head(self.manager, head)
        for payload in segments:
            document = loads(payload)
            if (
                type(document) is not dict
                or document.get("schema_version")
                not in {_SCHEMA_VERSION, _LEGACY_VERSION, "7", "8", "9", "10"}
                or set(document) != {"records", "schema_version"}
                or type(document.get("records")) is not list
            ):
                raise CheckpointCorruptionError("StateManager checkpoint delta schema is invalid")
            for row in document["records"]:
                if type(row) is not list or len(row) != 3 or type(row[0]) is not str:
                    raise CheckpointCorruptionError("StateManager checkpoint delta row is invalid")
                _apply_incremental_record(
                    self.manager,
                    row[0],
                    decode_state_value(row[1]),
                    decode_state_value(row[2]),
                )
        self._pending_records = []
        self._prepared_sequence = None
        self._prepared_record_count = 0
        self._prepared_seal = None
        self.manager._checkpoint_incremental_recorder = self._record_incremental_value


__all__ = ["StateManagerParticipant"]
