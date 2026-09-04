"""Small explicit checkpoint head for generation-engine progress state."""

from __future__ import annotations

import random
from datetime import UTC, datetime
from types import SimpleNamespace

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.timing import HawkesState

from .errors import CheckpointCorruptionError
from .owner_inventory import (
    GENERATION_ENGINE_CHECKPOINT_FIELDS,
    assert_owner_inventory_covers,
    assert_transient_owner_state_empty,
)
from .packed import dumps, loads
from .participants import ParticipantSeal
from .state_values import decode_state_value, encode_state_value
from .store import HeadDraft

_SCHEMA_VERSION = "4"
_SIMPLE_FIELDS = tuple(
    field.name
    for field in GENERATION_ENGINE_CHECKPOINT_FIELDS
    if field.disposition == "bounded-live-head"
    and field.name not in {"_dhcp_lease_state", "_hawkes_states", "_storyline_staged_archives"}
)
_SIMPLE_FIELD_SET = frozenset(_SIMPLE_FIELDS)


class _EngineHead(BaseModel):
    """Validated envelope for scheduling and report continuity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    fields: dict[str, object] = Field(default_factory=dict)
    dhcp_leases: list[list[object]] = Field(default_factory=list)
    hawkes_states: list[list[object]] = Field(default_factory=list)
    staged_archives: list[list[object]] = Field(default_factory=list)


def _restore_system_pids(engine: GenerationEngine, value: object) -> None:
    """Restore the evolved service-role map without breaking shared aliases."""

    if type(value) is not dict:
        raise CheckpointCorruptionError("generation checkpoint system PID map is invalid")
    hostnames = {system.hostname for system in engine.scenario.environment.systems}
    restored: dict[str, dict[str, int]] = {}
    for hostname, roles in value.items():
        if type(hostname) is not str or hostname not in hostnames or type(roles) is not dict:
            raise CheckpointCorruptionError("generation checkpoint system PID map is invalid")
        restored_roles: dict[str, int] = {}
        for role, pid in roles.items():
            if type(role) is not str or not role or type(pid) is not int or pid <= 0:
                raise CheckpointCorruptionError("generation checkpoint system PID map is invalid")
            restored_roles[role] = pid
        restored[hostname] = restored_roles
    current = getattr(engine, "_system_pids", None)
    if type(current) is dict:
        current.clear()
        current.update(restored)
    else:
        engine._system_pids = restored


def _capture_dhcp(engine: GenerationEngine) -> list[list[object]]:
    rows: list[list[object]] = []
    for hostname, state in sorted(engine._dhcp_lease_state.items()):
        if type(hostname) is not str or type(state) is not dict:
            raise TypeError("generation checkpoint DHCP state is invalid")
        normalized = dict(state)
        system = normalized.pop("system", None)
        if not isinstance(system, System) or system.hostname != hostname:
            raise TypeError("generation checkpoint DHCP system identity is invalid")
        rows.append([hostname, encode_state_value(normalized)])
    return rows


def _restore_dhcp(engine: GenerationEngine, rows: object) -> dict[str, dict[str, object]]:
    if type(rows) is not list:
        raise CheckpointCorruptionError("generation checkpoint DHCP table is invalid")
    systems = {system.hostname: system for system in engine.scenario.environment.systems}
    restored: dict[str, dict[str, object]] = {}
    for row in rows:
        if type(row) is not list or len(row) != 2 or type(row[0]) is not str:
            raise CheckpointCorruptionError("generation checkpoint DHCP row is invalid")
        hostname = row[0]
        system = systems.get(hostname)
        decoded = decode_state_value(row[1])
        if system is None or type(decoded) is not dict or hostname in restored:
            raise CheckpointCorruptionError("generation checkpoint DHCP row is invalid")
        if not isinstance(decoded.get("renewal_rng"), random.Random):
            raise CheckpointCorruptionError("generation checkpoint DHCP RNG is invalid")
        decoded["system"] = system
        restored[hostname] = decoded  # type: ignore[assignment]
    return restored


def _capture_staged_archives(engine: GenerationEngine) -> list[list[object]]:
    """Capture only unconsumed authored archives that can still affect exfiltration."""

    rows: list[list[object]] = []
    expected_fields = {
        "actor",
        "staging_host",
        "staging_ip",
        "source_ip",
        "archive_path",
        "smb_filename",
        "staged_at",
        "consumed",
    }
    for archive in getattr(engine, "_storyline_staged_archives", ()):
        if type(archive) is not SimpleNamespace or set(vars(archive)) != expected_fields:
            raise TypeError("generation checkpoint staged archive is invalid")
        if archive.consumed:
            continue
        if (
            type(archive.actor) is not User
            or any(
                type(getattr(archive, field)) is not str
                for field in (
                    "staging_host",
                    "staging_ip",
                    "source_ip",
                    "archive_path",
                    "smb_filename",
                )
            )
            or type(archive.staged_at) is not datetime
            or archive.staged_at.tzinfo is not UTC
            or type(archive.consumed) is not bool
        ):
            raise TypeError("generation checkpoint staged archive fields are invalid")
        rows.append(
            [
                archive.actor.username,
                archive.staging_host,
                archive.staging_ip,
                archive.source_ip,
                archive.archive_path,
                archive.smb_filename,
                archive.staged_at.isoformat(),
            ]
        )
    return rows


def _restore_staged_archives(
    engine: GenerationEngine,
    rows: object,
) -> list[SimpleNamespace]:
    """Rebind staged archive actors to the freshly compiled scenario."""

    if type(rows) is not list:
        raise CheckpointCorruptionError("generation checkpoint staged archive table is invalid")
    users = {user.username: user for user in engine.scenario.environment.users}
    restored: list[SimpleNamespace] = []
    for row in rows:
        if (
            type(row) is not list
            or len(row) != 7
            or any(type(value) is not str for value in row)
            or not row[0]
            or row[0] not in users
        ):
            raise CheckpointCorruptionError("generation checkpoint staged archive row is invalid")
        try:
            staged_at = datetime.fromisoformat(row[6])
        except ValueError as error:
            raise CheckpointCorruptionError(
                "generation checkpoint staged archive timestamp is invalid"
            ) from error
        if staged_at.tzinfo is not UTC:
            raise CheckpointCorruptionError(
                "generation checkpoint staged archive timestamp must be UTC"
            )
        restored.append(
            SimpleNamespace(
                actor=users[row[0]],
                staging_host=row[1],
                staging_ip=row[2],
                source_ip=row[3],
                archive_path=row[4],
                smb_filename=row[5],
                staged_at=staged_at,
                consumed=False,
            )
        )
    return restored


class GenerationEngineParticipant:
    """Persist only history-sensitive engine scheduling and reporting fields."""

    checkpoint_owner = "generation-engine"
    checkpoint_restore_priority = 50
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = GENERATION_ENGINE_CHECKPOINT_FIELDS

    def __init__(self, engine: GenerationEngine) -> None:
        self.engine = engine

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Capture bounded engine progress after rejecting terminal/transient work."""

        del sequence
        assert_owner_inventory_covers(
            self.engine,
            self.checkpoint_state_fields,
            owner_name="GenerationEngine",
        )
        assert_transient_owner_state_empty(
            self.engine,
            self.checkpoint_state_fields,
            owner_name="GenerationEngine",
            allow_unmaterialized=True,
        )
        hawkes = [
            [key, value.last_event_time, value.auxiliary_intensity]
            for key, value in sorted(self.engine._hawkes_states.items())
        ]
        if any(type(row[0]) is not str for row in hawkes):
            raise TypeError("generation checkpoint Hawkes state key is invalid")
        document = _EngineHead(
            schema_version=self.checkpoint_schema_version,
            fields={
                name: encode_state_value(getattr(self.engine, name))
                for name in _SIMPLE_FIELDS
                if hasattr(self.engine, name)
            },
            dhcp_leases=_capture_dhcp(self.engine),
            hawkes_states=hawkes,
            staged_archives=_capture_staged_archives(self.engine),
        )
        return ParticipantSeal(
            head=HeadDraft(
                owner=self.checkpoint_owner,
                schema_version=self.checkpoint_schema_version,
                payload=dumps(document.model_dump(mode="python")),
            )
        )

    def checkpoint_committed(self, sequence: int) -> None:
        """The bounded head owns no delta watermark."""

        del sequence

    def checkpoint_aborted(self, sequence: int) -> None:
        """The bounded head owns no prepared publication state."""

        del sequence

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Restore scheduling continuity into a freshly initialized engine."""

        if segments:
            raise CheckpointCorruptionError("generation engine checkpoint has unexpected segments")
        try:
            document = _EngineHead.model_validate(loads(head))
        except (TypeError, ValueError, ValidationError) as error:
            raise CheckpointCorruptionError(
                "generation engine checkpoint head is invalid"
            ) from error
        if document.schema_version != self.checkpoint_schema_version:
            raise CheckpointCorruptionError("generation engine checkpoint schema is unsupported")
        if not set(document.fields) <= _SIMPLE_FIELD_SET:
            raise CheckpointCorruptionError("generation engine checkpoint field set changed")
        decoded = {name: decode_state_value(value) for name, value in document.fields.items()}
        hawkes: dict[str, HawkesState] = {}
        for row in document.hawkes_states:
            if (
                type(row) is not list
                or len(row) != 3
                or type(row[0]) is not str
                or type(row[1]) not in {int, float}
                or type(row[2]) not in {int, float}
                or row[0] in hawkes
            ):
                raise CheckpointCorruptionError("generation checkpoint Hawkes row is invalid")
            hawkes[row[0]] = HawkesState(float(row[1]), float(row[2]))
        for name, value in decoded.items():
            if name == "_system_pids":
                _restore_system_pids(self.engine, value)
            else:
                setattr(self.engine, name, value)
        self.engine._dhcp_lease_state = _restore_dhcp(self.engine, document.dhcp_leases)
        self.engine._hawkes_states = hawkes
        self.engine._storyline_staged_archives = _restore_staged_archives(
            self.engine,
            document.staged_archives,
        )
