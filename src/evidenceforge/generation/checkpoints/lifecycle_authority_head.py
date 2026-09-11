"""Bounded checkpoint head for generator-local lifecycle scheduling authority."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.events.lifecycle import LifecycleEntityRef
from evidenceforge.generation.lifecycle_authority import (
    DeferredLifecycleCloseIntent,
    GeneratorLifecycleAuthority,
    ProcessCloseIntent,
    _AuthorityShard,
    _StrictLifecycleMarker,
)
from evidenceforge.models.scenario import System

from .errors import CheckpointCorruptionError, CheckpointError
from .owner_inventory import (
    GENERATOR_LIFECYCLE_AUTHORITY_CHECKPOINT_FIELDS,
    GENERATOR_LIFECYCLE_AUTHORITY_SHARD_CHECKPOINT_FIELDS,
    assert_complete_owner_inventory,
    assert_transient_owner_state_empty,
)
from .packed import dumps, loads
from .participants import ParticipantSeal
from .state_values import decode_state_value, encode_state_value
from .store import HeadDraft

_SCHEMA_VERSION = "1"


class _LifecycleAuthorityHead(BaseModel):
    """Validated envelope for bounded future-close and strict-owner state."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    shard_count: int = Field(gt=0)
    bootstrap_complete: bool
    bootstrapped_sessions: int = Field(ge=0)
    bootstrapped_processes: int = Field(ge=0)
    watermark: str | None = None
    process_closes: list[list[object]] = Field(default_factory=list)
    deferred_closes: list[list[object]] = Field(default_factory=list)
    strict_markers: list[list[object]] = Field(default_factory=list)


def _time(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _decode_time(value: object, *, optional: bool = False) -> datetime | None:
    if value is None and optional:
        return None
    if type(value) is not str:
        raise CheckpointCorruptionError("lifecycle-authority checkpoint time is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise CheckpointCorruptionError("lifecycle-authority checkpoint time is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CheckpointCorruptionError("lifecycle-authority checkpoint time lacks a UTC offset")
    return parsed


def _row(value: object, *, width: int, label: str) -> list[object]:
    if type(value) is not list or len(value) != width:
        raise CheckpointCorruptionError(f"lifecycle-authority checkpoint {label} row is invalid")
    return value


def _install_shard(authority: GeneratorLifecycleAuthority, shard_id: int) -> _AuthorityShard:
    if not 0 <= shard_id < authority._shard_count:
        raise CheckpointCorruptionError("lifecycle-authority checkpoint shard is invalid")
    shard = authority._shards[shard_id]
    if shard is None:
        shard = _AuthorityShard()
        authority._shards[shard_id] = shard
    return shard


class GeneratorLifecycleAuthorityParticipant:
    """Persist pending close work and strict lifecycle gates without capability graphs."""

    checkpoint_owner = "generator-lifecycle-authority"
    checkpoint_restore_priority = 25
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = GENERATOR_LIFECYCLE_AUTHORITY_CHECKPOINT_FIELDS

    def __init__(
        self,
        authority: GeneratorLifecycleAuthority,
        *,
        systems: tuple[System, ...],
    ) -> None:
        self.authority = authority
        self._systems = {system.hostname: system for system in systems}
        if len(self._systems) != len(systems):
            raise ValueError("lifecycle-authority checkpoint systems must have unique hostnames")

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Capture bounded queues after rejecting all in-flight authority state."""

        del sequence
        assert_transient_owner_state_empty(
            self.authority,
            self.checkpoint_state_fields,
            owner_name="GeneratorLifecycleAuthority",
        )
        self._validate_restart_discardable_proofs()
        process_rows: list[list[object]] = []
        deferred_rows: list[list[object]] = []
        strict_rows: list[list[object]] = []
        for shard_id, shard in enumerate(self.authority._shards):
            if shard is None:
                continue
            assert_complete_owner_inventory(
                shard,
                GENERATOR_LIFECYCLE_AUTHORITY_SHARD_CHECKPOINT_FIELDS,
                owner_name=f"GeneratorLifecycleAuthority shard {shard_id}",
            )
            with shard.lock:
                for intent in shard.process_closes.iter_values_by_handle():
                    process_rows.append(
                        [
                            shard_id,
                            intent.system.hostname,
                            intent.pid,
                            _time(intent.started_at),
                            intent.process_object_id,
                            intent.username,
                            intent.process_name,
                            intent.logon_id,
                            _time(intent.close_at),
                            intent.action_id,
                            intent.transition_ordinal,
                            _time(intent.eligible_at),
                        ]
                    )
                for intent in shard.deferred_closes.iter_values_by_handle():
                    deferred_rows.append(
                        [
                            shard_id,
                            intent.close_id,
                            intent.hostname,
                            intent.session_object_id,
                            _time(intent.close_at),
                            intent.action_id,
                            encode_state_value(intent.payload),
                            intent.transition_ordinal,
                        ]
                    )
                for marker in shard.strict_markers.iter_values_by_handle():
                    strict_rows.append(
                        [
                            shard_id,
                            marker.key[0],
                            marker.key[1],
                            _time(marker.retain_until),
                        ]
                    )
        document = _LifecycleAuthorityHead(
            schema_version=self.checkpoint_schema_version,
            shard_count=self.authority._shard_count,
            bootstrap_complete=self.authority._bootstrap_complete,
            bootstrapped_sessions=self.authority._bootstrapped_sessions,
            bootstrapped_processes=self.authority._bootstrapped_processes,
            watermark=_time(self.authority._watermark),
            process_closes=process_rows,
            deferred_closes=deferred_rows,
            strict_markers=strict_rows,
        )
        return ParticipantSeal(
            head=HeadDraft(
                owner=self.checkpoint_owner,
                schema_version=self.checkpoint_schema_version,
                payload=dumps(document.model_dump(mode="python")),
            )
        )

    def _validate_restart_discardable_proofs(self) -> None:
        """Reject retry records that still own unfinished work across a restart."""

        authority = self.authority
        with authority._materialization_batch_transaction_lock:
            records = authority._materialization_batch_transactions
            if (
                authority._materialization_batch_transactions_pending != 0
                or authority._materialization_batch_transactions_unacknowledged != 0
                or authority._materialization_batch_transactions_acknowledged != len(records)
                or any(
                    not record.acknowledged
                    or record.terminal_result is None
                    or record.claimed_thread is not None
                    or record.planning_attempt is not None
                    or record.planning_capability is not None
                    for record in records.values()
                )
            ):
                raise CheckpointError(
                    "lifecycle-authority checkpoint retains unfinished batch work"
                )
        for facts in authority._acknowledged_prepared_network_receipts.values():
            if facts.receipt_ref() is None:
                continue
            if not facts.detached_values or not facts.detached_proof:
                raise CheckpointError(
                    "lifecycle-authority checkpoint retains invalid acknowledged proof state"
                )

    def checkpoint_committed(self, sequence: int) -> None:
        """The bounded head owns no incremental watermark."""

        del sequence

    def checkpoint_aborted(self, sequence: int) -> None:
        """The bounded head owns no prepared publication state."""

        del sequence

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Restore queues into fresh shards and rebuild their indexes and deadline heaps."""

        if segments:
            raise CheckpointCorruptionError(
                "lifecycle-authority checkpoint has unexpected segments"
            )
        try:
            document = _LifecycleAuthorityHead.model_validate(loads(head))
        except (TypeError, ValueError, ValidationError) as error:
            raise CheckpointCorruptionError(
                "lifecycle-authority checkpoint head is invalid"
            ) from error
        if document.schema_version != self.checkpoint_schema_version:
            raise CheckpointCorruptionError("lifecycle-authority checkpoint schema is unsupported")
        if document.shard_count != self.authority._shard_count:
            raise CheckpointCorruptionError("lifecycle-authority checkpoint shard count changed")
        self.authority._shards = [None] * self.authority._shard_count
        self.authority._materialization_batch_transactions.clear()
        self.authority._materialization_batch_transactions_pending = 0
        self.authority._materialization_batch_transactions_unacknowledged = 0
        self.authority._materialization_batch_transactions_acknowledged = 0
        self.authority._materialization_batch_transaction_retained_bytes = 0
        self.authority._acknowledged_prepared_network_receipts.clear()
        self.authority._detached_network_receipt_bindings.clear()
        process_keys: set[tuple[str, int, datetime | None]] = set()
        deferred_ids: set[str] = set()
        strict_keys: set[tuple[int, str, str]] = set()
        for encoded in document.process_closes:
            row = _row(encoded, width=12, label="process close")
            (
                shard_id,
                hostname,
                pid,
                started_at,
                process_object_id,
                username,
                process_name,
                logon_id,
                close_at,
                action_id,
                transition_ordinal,
                eligible_at,
            ) = row
            if (
                type(shard_id) is not int
                or type(hostname) is not str
                or type(pid) is not int
                or type(process_object_id) is not str
                or type(username) is not str
                or type(process_name) is not str
                or type(logon_id) is not str
                or type(action_id) is not str
                or type(transition_ordinal) is not int
            ):
                raise CheckpointCorruptionError(
                    "lifecycle-authority checkpoint process close is invalid"
                )
            system = self._systems.get(hostname)
            if system is None or self.authority._shard_id(hostname) != shard_id:
                raise CheckpointCorruptionError(
                    "lifecycle-authority checkpoint process system is invalid"
                )
            try:
                intent = ProcessCloseIntent(
                    system=system,
                    pid=pid,
                    started_at=_decode_time(started_at, optional=True),
                    process_object_id=process_object_id,
                    username=username,
                    process_name=process_name,
                    logon_id=logon_id,
                    close_at=_decode_time(close_at),  # type: ignore[arg-type]
                    action_id=action_id,
                    transition_ordinal=transition_ordinal,
                    eligible_at=_decode_time(eligible_at, optional=True),
                )
            except (TypeError, ValueError) as error:
                raise CheckpointCorruptionError(
                    "lifecycle-authority checkpoint process close is invalid"
                ) from error
            if intent.key in process_keys:
                raise CheckpointCorruptionError(
                    "lifecycle-authority checkpoint process close is duplicated"
                )
            process_keys.add(intent.key)
            shard = _install_shard(self.authority, shard_id)
            shard.process_closes[intent.key] = intent
            handle = shard.process_closes.handle_for(intent.key)
            shard.process_close_deadlines.set(handle, intent.close_at.timestamp())
            shard.process_close_order.push(handle, intent)
        for encoded in document.deferred_closes:
            row = _row(encoded, width=8, label="deferred close")
            (
                shard_id,
                close_id,
                hostname,
                session_object_id,
                close_at,
                action_id,
                payload,
                transition_ordinal,
            ) = row
            if (
                type(shard_id) is not int
                or type(close_id) is not str
                or type(hostname) is not str
                or type(session_object_id) is not str
                or type(action_id) is not str
                or type(transition_ordinal) is not int
                or self.authority._shard_id(hostname) != shard_id
            ):
                raise CheckpointCorruptionError(
                    "lifecycle-authority checkpoint deferred close is invalid"
                )
            try:
                intent = DeferredLifecycleCloseIntent(
                    close_id=close_id,
                    hostname=hostname,
                    session_object_id=session_object_id,
                    close_at=_decode_time(close_at),  # type: ignore[arg-type]
                    action_id=action_id,
                    payload=decode_state_value(payload),
                    transition_ordinal=transition_ordinal,
                )
            except (TypeError, ValueError) as error:
                raise CheckpointCorruptionError(
                    "lifecycle-authority checkpoint deferred close is invalid"
                ) from error
            if close_id in deferred_ids:
                raise CheckpointCorruptionError(
                    "lifecycle-authority checkpoint deferred close is duplicated"
                )
            deferred_ids.add(close_id)
            shard = _install_shard(self.authority, shard_id)
            shard.deferred_closes[close_id] = intent
            handle = shard.deferred_closes.handle_for(close_id)
            shard.deferred_close_deadlines.set(handle, intent.close_at.timestamp())
            shard.deferred_close_order.push(handle, intent)
        for encoded in document.strict_markers:
            shard_id, kind, object_id, retain_until = _row(encoded, width=4, label="strict marker")
            if type(shard_id) is not int or type(kind) is not str or type(object_id) is not str:
                raise CheckpointCorruptionError(
                    "lifecycle-authority checkpoint strict marker is invalid"
                )
            try:
                subject = LifecycleEntityRef(kind, object_id)  # type: ignore[arg-type]
                deadline = _decode_time(retain_until)
            except (TypeError, ValueError) as error:
                raise CheckpointCorruptionError(
                    "lifecycle-authority checkpoint strict marker is invalid"
                ) from error
            key = (shard_id, subject.kind, subject.object_id)
            if key in strict_keys:
                raise CheckpointCorruptionError(
                    "lifecycle-authority checkpoint strict marker is duplicated"
                )
            strict_keys.add(key)
            shard = _install_shard(self.authority, shard_id)
            marker = _StrictLifecycleMarker((subject.kind, subject.object_id), deadline)  # type: ignore[arg-type]
            shard.strict_markers[marker.key] = marker
            shard.strict_deadlines.set(
                shard.strict_markers.handle_for(marker.key),
                deadline.timestamp(),  # type: ignore[union-attr]
            )
        self.authority._bootstrap_complete = document.bootstrap_complete
        self.authority._bootstrapped_sessions = document.bootstrapped_sessions
        self.authority._bootstrapped_processes = document.bootstrapped_processes
        self.authority._watermark = _decode_time(document.watermark, optional=True)


__all__ = ["GeneratorLifecycleAuthorityParticipant"]
