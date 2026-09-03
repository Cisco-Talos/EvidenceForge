"""Bounded semantic checkpoint head for direct ActivityGenerator runtime state."""

from __future__ import annotations

import math
from collections.abc import Hashable
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.generation.activity.generator import ActivityGenerator
from evidenceforge.generation.indexes import ExpiringIndex
from evidenceforge.generation.process_runtime_cache import BoundedRuntimeCache
from evidenceforge.models.scenario import System

from .errors import CheckpointCorruptionError, CheckpointError
from .owner_inventory import (
    BOUNDED_RUNTIME_CACHE_CHECKPOINT_FIELDS,
    EXPIRING_INDEX_CHECKPOINT_FIELDS,
    assert_complete_owner_inventory,
)
from .packed import dumps, loads
from .participants import OwnerStateField, ParticipantSeal
from .state_values import decode_state_value, encode_state_value
from .store import HeadDraft

_SCHEMA_VERSION = "1"

# These are the bounded, output-affecting leaves owned directly by ActivityGenerator. Shared
# managers and protocol registries have separate participants; scenario indexes are rebuilt.
_DIRECT_FIELDS = (
    "_bash_history_command_counts",
    "_bash_history_next_time",
    "_bash_history_quick_streaks",
    "_bash_history_user_seconds",
    "_created_account_sids",
    "_foreground_shell_next_time",
    "_foreground_shell_release_groups",
    "_kerberos_cache",
    "_kerberos_source_port_reservations",
    "_kerberos_tgt_cache_until",
    "_last_browser_launch_by_session",
    "_last_one_shot_cli_launch_by_command",
    "_last_one_shot_cli_launch_by_exe",
    "_last_workstation_lock_time",
    "_linux_apt_frontends",
    "_linux_local_logon_syslog_sessions",
    "_linux_shell_last_session_close",
    "_linux_sudo_tty_assignments",
    "_linux_sudo_tty_available",
    "_linux_sudo_tty_keys_by_logon_id",
    "_linux_sudo_tty_owners",
    "_linux_sudo_tty_sessions",
    "_loaded_modules_by_process",
    "_next_icmp_observation_ts_us",
    "_ntp_association_profiles",
    "_ntp_last_parser_times",
    "_ntp_server_response_profiles",
    "_postfix_qmgr_pid_cache",
    "_preferred_browser_by_session",
    "_privileged_auth_occurrences",
    "_process_connection_hold_until",
    "_process_source_create_bounds",
    "_process_source_create_latest",
    "_process_source_create_times",
    "_process_source_terminate_latest",
    "_process_source_terminate_times",
    "_proxy_auth_session_deadlines",
    "_session_process_source_terminate_times",
    "_singleton_application_intervals",
    "_smb_responder_pids",
    "_ssh_pid_aliases",
    "_ssh_responder_pids",
    "_ssh_session_ready_times",
    "_terminated_process_keys",
    "_terminated_process_latest",
    "_terminated_process_times",
    "_top_level_browser_launch_targets",
    "_user_process_history",
    "_visible_account_created_at",
    "_visible_account_kerberos_transport_emitted",
    "sid_registry",
)
_SCALAR_FIELDS = (
    "_dns_cache_last_prune",
    "_domain_sid_prefix",
    "_linux_sudo_logoff_high_water_pending",
    "_max_rid",
    "_next_sid_reservation_id",
    "_proxy_channel_watermark",
    "_rdp_lifecycle_watermark",
)
_EXPIRING_FIELDS = (
    "_dns_cache",
    "_recent_connection_tuples",
)
_BOUNDED_CACHE_FIELDS = (
    "_failed_logon_attempt_times",
    "_ssh_source_ports",
)
_FOREGROUND_FINALIZERS = "_foreground_process_finalizers"
_TRANSIENT_EMPTY_FIELDS = (
    "_expanding_types",
    "_failed_logon_attempt_pending",
    "_linux_sudo_tty_capacity_claims",
    "_pending_linux_sudo_logoffs",
    "_pending_rdp_lifecycle_continuations",
    "_pending_ssh_manager_closures",
    "_pending_ssh_session_closures",
    "_postfix_queue_states",
    "_prepared_rdp_lifecycle_continuations",
    "_prepared_ssh_close_continuations",
    "_process_close_in_progress",
    "_sid_reservation_groups",
    "_sid_reservations",
)
_REBUILT_FIELDS = (
    "_all_system_ips",
    "_db_servers",
    "_dc_hostnames",
    "_dc_ips",
    "_dc_systems",
    "_dns_server_ips",
    "_email_corpus_cache",
    "_ip_to_system",
    "_production_process_runtime_caches",
    "_proxy_routes",
    "_proxy_service_accounts",
    "_system_pids",
    "_systems_by_hostname",
    "_users_by_username",
)
_INCREMENTAL_FIELDS = ("_email_artifact_manifest_spool",)

_ALL_FIELD_GROUPS = (
    (*_DIRECT_FIELDS, *_SCALAR_FIELDS, *_EXPIRING_FIELDS, *_BOUNDED_CACHE_FIELDS),
    (_FOREGROUND_FINALIZERS,),
    _TRANSIENT_EMPTY_FIELDS,
    _REBUILT_FIELDS,
    _INCREMENTAL_FIELDS,
)
if sum((len(group) for group in _ALL_FIELD_GROUPS), start=0) != len(
    set().union(*map(set, _ALL_FIELD_GROUPS))
):
    raise RuntimeError("activity checkpoint field classification contains a duplicate")


class _ActivityHead(BaseModel):
    """Validated envelope for bounded direct activity state."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    fields: dict[str, object] = Field(default_factory=dict)
    expiring: dict[str, list[list[object]]] = Field(default_factory=dict)
    bounded_caches: dict[str, list[object]] = Field(default_factory=dict)
    foreground_finalizers: list[list[object]] = Field(default_factory=list)


def _capture_expiring(index: ExpiringIndex[Hashable, object]) -> list[list[object]]:
    return [
        [
            encode_state_value(key),
            encode_state_value(value),
            float(deadline),
            order,
            protected,
        ]
        for key, value, deadline, order, protected in index.checkpoint_records()
    ]


def _decode_expiring(value: object) -> tuple[tuple[Hashable, object, float, int, bool], ...]:
    if type(value) is not list:
        raise CheckpointCorruptionError("activity checkpoint expiring table is invalid")
    rows: list[tuple[Hashable, object, float, int, bool]] = []
    for row in value:
        if (
            type(row) is not list
            or len(row) != 5
            or type(row[2]) is not float
            or not math.isfinite(row[2])
            or type(row[3]) is not int
            or type(row[4]) is not bool
        ):
            raise CheckpointCorruptionError("activity checkpoint expiring row is invalid")
        key = decode_state_value(row[0])
        try:
            hash(key)
        except TypeError as error:
            raise CheckpointCorruptionError(
                "activity checkpoint expiring key is unhashable"
            ) from error
        rows.append((key, decode_state_value(row[1]), row[2], row[3], row[4]))  # type: ignore[arg-type]
    return tuple(rows)


def _capture_bounded(cache: BoundedRuntimeCache[Hashable, object]) -> list[object]:
    return [
        encode_state_value(cache.watermark),
        [
            [encode_state_value(key), encode_state_value(value), deadline]
            for key, value, deadline in cache.checkpoint_records()
        ],
    ]


def _decode_bounded(
    value: object,
) -> tuple[datetime | None, tuple[tuple[Hashable, object, float], ...]]:
    if type(value) is not list or len(value) != 2 or type(value[1]) is not list:
        raise CheckpointCorruptionError("activity checkpoint bounded cache is invalid")
    watermark = decode_state_value(value[0])
    if watermark is not None and (type(watermark) is not datetime or watermark.tzinfo is not UTC):
        raise CheckpointCorruptionError("activity checkpoint cache watermark is invalid")
    rows: list[tuple[Hashable, object, float]] = []
    seen: set[Hashable] = set()
    for row in value[1]:
        if (
            type(row) is not list
            or len(row) != 3
            or type(row[2]) is not float
            or not math.isfinite(row[2])
        ):
            raise CheckpointCorruptionError("activity checkpoint cache row is invalid")
        key = decode_state_value(row[0])
        try:
            duplicate = key in seen
        except TypeError as error:
            raise CheckpointCorruptionError(
                "activity checkpoint cache key is unhashable"
            ) from error
        if duplicate:
            raise CheckpointCorruptionError("activity checkpoint cache key is duplicated")
        seen.add(key)  # type: ignore[arg-type]
        rows.append((key, decode_state_value(row[1]), row[2]))  # type: ignore[arg-type]
    return watermark, tuple(rows)


def _capture_foreground(generator: ActivityGenerator) -> list[list[object]]:
    rows: list[list[object]] = []
    index = generator._foreground_process_finalizers
    for key, value, deadline, order, protected in index.checkpoint_records():
        system, username, process_name, logon_id, finalizer_time = value
        if not isinstance(system, System):
            raise TypeError("activity checkpoint foreground system is invalid")
        rows.append(
            [
                encode_state_value(key),
                system.hostname,
                username,
                process_name,
                logon_id,
                encode_state_value(finalizer_time),
                float(deadline),
                order,
                protected,
            ]
        )
    return rows


def _restore_foreground(generator: ActivityGenerator, rows: object) -> None:
    if type(rows) is not list:
        raise CheckpointCorruptionError("activity checkpoint foreground table is invalid")
    systems = {system.hostname: system for system in generator._scenario_environment.systems}
    records: list[tuple[Hashable, object, float, int, bool]] = []
    for row in rows:
        if (
            type(row) is not list
            or len(row) != 9
            or any(type(row[index]) is not str or not row[index] for index in range(1, 5))
            or type(row[6]) is not float
            or not math.isfinite(row[6])
            or type(row[7]) is not int
            or type(row[8]) is not bool
        ):
            raise CheckpointCorruptionError("activity checkpoint foreground row is invalid")
        key = decode_state_value(row[0])
        finalizer_time = decode_state_value(row[5])
        system = systems.get(row[1])
        if (
            type(key) is not tuple
            or system is None
            or type(finalizer_time) is not datetime
            or finalizer_time.tzinfo is not UTC
        ):
            raise CheckpointCorruptionError("activity checkpoint foreground row is invalid")
        records.append(
            (
                key,
                (system, row[2], row[3], row[4], finalizer_time),
                row[6],
                row[7],
                row[8],
            )
        )
    generator._foreground_process_finalizers.restore_checkpoint_records(tuple(records))


def _assert_transient_empty(generator: ActivityGenerator) -> None:
    nonempty: list[str] = []
    for name in _TRANSIENT_EMPTY_FIELDS:
        value = getattr(generator, name, None)
        if value is None or value is False or value == 0:
            continue
        try:
            empty = len(value) == 0
        except TypeError:
            empty = False
        if not empty:
            nonempty.append(name)
    if nonempty:
        raise CheckpointError(
            f"activity checkpoint barrier retains transient state: {sorted(nonempty)}"
        )


class ActivityGeneratorStateParticipant:
    """Persist bounded direct activity state; shared managers remain external."""

    checkpoint_owner = "activity-generator"
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = tuple(
        sorted(
            (
                *(
                    OwnerStateField(name, "bounded-live-head")
                    for name in (
                        *_DIRECT_FIELDS,
                        *_SCALAR_FIELDS,
                        *_EXPIRING_FIELDS,
                        *_BOUNDED_CACHE_FIELDS,
                        _FOREGROUND_FINALIZERS,
                    )
                ),
                *(
                    OwnerStateField(name, "transient-empty-at-barrier")
                    for name in _TRANSIENT_EMPTY_FIELDS
                ),
                *(OwnerStateField(name, "deterministically-rebuilt") for name in _REBUILT_FIELDS),
                *(
                    OwnerStateField(name, "immutable-incremental-segments")
                    for name in _INCREMENTAL_FIELDS
                ),
            ),
            key=lambda field: field.name,
        )
    )

    def __init__(self, generator: ActivityGenerator) -> None:
        self.generator = generator

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Capture bounded leaves after rejecting in-flight and deferred work."""

        del sequence
        _assert_transient_empty(self.generator)
        for name in _EXPIRING_FIELDS:
            assert_complete_owner_inventory(
                getattr(self.generator, name),
                EXPIRING_INDEX_CHECKPOINT_FIELDS,
                owner_name=f"ActivityGenerator.{name}",
            )
        assert_complete_owner_inventory(
            self.generator._foreground_process_finalizers,
            EXPIRING_INDEX_CHECKPOINT_FIELDS,
            owner_name="ActivityGenerator._foreground_process_finalizers",
        )
        for name in _BOUNDED_CACHE_FIELDS:
            assert_complete_owner_inventory(
                getattr(self.generator, name),
                BOUNDED_RUNTIME_CACHE_CHECKPOINT_FIELDS,
                owner_name=f"ActivityGenerator.{name}",
            )
        fields = {
            name: encode_state_value(getattr(self.generator, name))
            for name in (*_DIRECT_FIELDS, *_SCALAR_FIELDS)
            if hasattr(self.generator, name)
        }
        expiring = {
            name: _capture_expiring(getattr(self.generator, name)) for name in _EXPIRING_FIELDS
        }
        bounded = {
            name: _capture_bounded(getattr(self.generator, name)) for name in _BOUNDED_CACHE_FIELDS
        }
        document = _ActivityHead(
            schema_version=self.checkpoint_schema_version,
            fields=fields,
            expiring=expiring,
            bounded_caches=bounded,
            foreground_finalizers=_capture_foreground(self.generator),
        )
        return ParticipantSeal(
            head=HeadDraft(
                owner=self.checkpoint_owner,
                schema_version=self.checkpoint_schema_version,
                payload=dumps(document.model_dump(mode="python")),
            )
        )

    def checkpoint_committed(self, sequence: int) -> None:
        """The bounded activity head owns no delta watermark."""

        del sequence

    def checkpoint_aborted(self, sequence: int) -> None:
        """The bounded activity head owns no prepared publication state."""

        del sequence

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Restore direct activity leaves into a freshly initialized generator."""

        if segments:
            raise CheckpointCorruptionError("activity checkpoint has unexpected segments")
        try:
            document = _ActivityHead.model_validate(loads(head))
            if document.schema_version != self.checkpoint_schema_version:
                raise CheckpointCorruptionError("activity checkpoint schema version changed")
            allowed_fields = {*_DIRECT_FIELDS, *_SCALAR_FIELDS}
            if (
                not set(document.fields) <= allowed_fields
                or set(document.expiring) != set(_EXPIRING_FIELDS)
                or set(document.bounded_caches) != set(_BOUNDED_CACHE_FIELDS)
            ):
                raise CheckpointCorruptionError("activity checkpoint field set changed")
            for name, value in document.fields.items():
                setattr(self.generator, name, decode_state_value(value))
            for name, rows in document.expiring.items():
                index = getattr(self.generator, name)
                index.restore_checkpoint_records(_decode_expiring(rows))
            for name, encoded in document.bounded_caches.items():
                watermark, records = _decode_bounded(encoded)
                cache = getattr(self.generator, name)
                cache.restore_checkpoint_records(records, watermark=watermark)
            _restore_foreground(self.generator, document.foreground_finalizers)
        except CheckpointCorruptionError:
            raise
        except (AttributeError, TypeError, ValueError, ValidationError) as error:
            raise CheckpointCorruptionError("activity checkpoint head is invalid") from error


__all__ = ["ActivityGeneratorStateParticipant"]
