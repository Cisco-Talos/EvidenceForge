"""Small explicit checkpoint head for generation-engine progress state."""

from __future__ import annotations

import random

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import System
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

_SCHEMA_VERSION = "1"
_SIMPLE_FIELDS = tuple(
    field.name
    for field in GENERATION_ENGINE_CHECKPOINT_FIELDS
    if field.disposition == "bounded-live-head"
    and field.name not in {"_dhcp_lease_state", "_hawkes_states"}
)
_SIMPLE_FIELD_SET = frozenset(_SIMPLE_FIELDS)


class _EngineHead(BaseModel):
    """Validated envelope for scheduling and report continuity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    fields: dict[str, object] = Field(default_factory=dict)
    dhcp_leases: list[list[object]] = Field(default_factory=list)
    hawkes_states: list[list[object]] = Field(default_factory=list)


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
            setattr(self.engine, name, value)
        self.engine._dhcp_lease_state = _restore_dhcp(self.engine, document.dhcp_leases)
        self.engine._hawkes_states = hawkes
