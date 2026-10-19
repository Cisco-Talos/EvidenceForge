# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded ES client sequencing before source filtering or delayed rendering.

This owner does not enable an ES emitter. A producer must supply an explicitly
opened client, subscriptions, initial counters and canonical delivery order.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from threading import RLock, get_ident
from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from evidenceforge.events.observation import ObservationDecision
from evidenceforge.models.exceptions import StateError

_MAX_NATIVE_ROW_BYTES = 1024 * 1024
_MAX_NATIVE_BATCH_BYTES = 16 * _MAX_NATIVE_ROW_BYTES

type _Counter = Annotated[int, Field(ge=0, lt=2**64)]
type _Name = Annotated[str, Field(min_length=1, max_length=256)]


class _Value(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ESEventCounter(_Value):
    """Next kernel sequence for one subscribed event type."""

    event_type: int = Field(ge=0, lt=2**32)
    next_sequence: _Counter


class ESKernelLoss(_Value):
    """Explicit lost messages for a subscribed event type before a delivery."""

    event_type: int = Field(ge=0, lt=2**32)
    count: _Counter


class ESCollectorProcess(_Value):
    """Exact execution owning an explicitly established ES connection."""

    object_id: _Name
    pid: int = Field(gt=0, lt=2**31)
    started_at: AwareDatetime
    execution_ordinal: int = Field(ge=0)
    execution_started_at: AwareDatetime

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if self.execution_started_at < self.started_at:
            raise ValueError("Collector execution cannot precede its lifetime")
        return self


class ESCollectorState(_Value):
    """One source instance's current connection, not its executable installation."""

    source_instance: _Name
    hostname: _Name
    generation: int = Field(ge=1)
    opened_at: AwareDatetime
    last_delivery_at: AwareDatetime
    next_delivery: int = Field(ge=0)
    next_global_sequence: _Counter
    event_counters: tuple[ESEventCounter, ...] = Field(min_length=1, max_length=256)
    process: ESCollectorProcess | None = None
    closed_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def consistent(self) -> Self:
        kinds = tuple(item.event_type for item in self.event_counters)
        if kinds != tuple(sorted(set(kinds))):
            raise ValueError("ES subscriptions require sorted unique event types")
        if self.last_delivery_at < self.opened_at:
            raise ValueError("ES delivery cannot precede the client connection")
        if self.process is not None and self.opened_at < self.process.execution_started_at:
            raise ValueError("Collector connection cannot precede its owning execution")
        if self.closed_at is not None and self.closed_at < self.last_delivery_at:
            raise ValueError("Collector closure cannot precede delivery")
        return self


class ESCollectorClosure(_Value):
    """Exact idle connection and canonical time for an explicit disconnect."""

    before: ESCollectorState
    closed_at: AwareDatetime

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if self.before.closed_at is not None or self.closed_at < self.before.last_delivery_at:
            raise ValueError("Collector closure requires an open connection after its deliveries")
        return self


class ESCollectorObservation(_Value):
    """Frozen counters and export decision, safe for later parallel rendering."""

    source_instance: _Name
    hostname: _Name
    generation: int = Field(ge=1)
    delivery: int = Field(ge=0)
    occurrence_id: _Name
    event_type: int = Field(ge=0, lt=2**32)
    observed_at: AwareDatetime
    collector_process: ESCollectorProcess | None = None
    seq_num: _Counter
    global_seq_num: _Counter
    status: Literal["visible", "delayed", "dropped", "filtered", "out_of_window"]
    delay: timedelta


@dataclass(frozen=True, slots=True)
class _NativeProjection:
    """Caller-retained bytes authenticated for one exact delivery or batch capability."""

    ndjson: str
    canonical_token: str | None
    proof: bytes = field(repr=False)


@dataclass(frozen=True, slots=True, eq=False)
class ESDeliveryPreparation:
    """Exact caller-held capability; terminal proof survives a lost commit return."""

    observation: ESCollectorObservation
    _proof: bytes = b""
    _native_projection: _NativeProjection | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class _Pending:
    capability: ESDeliveryPreparation
    after: ESCollectorState
    observation: ESCollectorObservation
    native_projection: _NativeProjection | None = None


@dataclass(frozen=True, slots=True)
class PreparedESDeliveryCommit:
    """Opaque lock-held counter commit for an outer atomic owner.

    The registry keeps every authoritative preimage and result. A copied or
    modified handle cannot supply replacement counters or completion proofs.
    """

    _registry: ESCollectorRegistry
    _source_instance: str

    @property
    def observation(self) -> ESCollectorObservation:
        """Return the registry-owned immutable observation while the claim is active."""
        return self._registry._delivery_claim(self).observation

    def freeze_native_projection(self, ndjson: str, *, canonical_token: str | None = None) -> str:
        """Bind exact prepared bytes before commit; retries cannot change them.

        Source preparation owns native semantics. This owner only authenticates
        a bounded opaque NDJSON line against its reserved counter observation.
        """
        return self._registry._freeze_native_projection(
            self, ndjson, canonical_token=canonical_token
        )

    @property
    def publication_token(self) -> str:
        """Return the prepared completion proof for an outer canonical receipt."""
        return self._registry._delivery_claim(self).proof.hex()

    @property
    def committed(self) -> bool:
        """Whether this active claim finalized its counter publication."""
        return self._registry._delivery_claim(self).committed

    def apply_provisional(self) -> None:
        """Apply counters under the retained lock, rolling back unless finalized."""
        self._registry._apply_claimed_delivery(self)

    def finalize_no_fail(self) -> None:
        """Publish the prepared completion proof after the outer owners commit."""
        self._registry._finalize_claimed_delivery(self)

    def commit_no_fail(self) -> None:
        """Apply and finalize the prevalidated counters for standalone callers."""
        self.apply_provisional()
        self.finalize_no_fail()


@dataclass(slots=True)
class _DeliveryClaim:
    handle: PreparedESDeliveryCommit
    capability: ESDeliveryPreparation
    observation: ESCollectorObservation
    after: ESCollectorState | None
    proof: bytes
    thread_id: int
    committed: bool = False
    native_projection: _NativeProjection | None = None
    before: ESCollectorState | None = None
    applied: bool = False


class ESDeliveryRequest(_Value):
    """One explicit ordered delivery in a bounded same-connection counter batch."""

    occurrence_id: _Name
    event_type: int = Field(ge=0, lt=2**32)
    observed_at: AwareDatetime
    decision: ObservationDecision
    kernel_lost: tuple[ESKernelLoss, ...] = Field(default=(), max_length=256)


@dataclass(frozen=True, slots=True, eq=False)
class ESDeliveryBatchPreparation:
    """Caller-held batch capability with a registry-authenticated completion proof."""

    observations: tuple[ESCollectorObservation, ...]
    _proof: bytes = b""
    _native_projection: _NativeProjection | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class _PendingBatch:
    capability: ESDeliveryBatchPreparation
    after: ESCollectorState
    observations: tuple[ESCollectorObservation, ...]
    native_projection: _NativeProjection | None = None


@dataclass(frozen=True, slots=True)
class PreparedESDeliveryBatchCommit:
    """Opaque same-thread batch commit handle; counter truth stays registry-owned."""

    _registry: ESCollectorRegistry
    _source_instance: str

    @property
    def observations(self) -> tuple[ESCollectorObservation, ...]:
        """Return the retained immutable observations while the exact claim is active."""
        return self._registry._batch_claim(self).observations

    def freeze_native_projections(
        self, rows: tuple[str, ...], *, canonical_token: str | None = None
    ) -> tuple[str, ...]:
        """Bind one ordered native row per reserved observation before publication."""
        return self._registry._freeze_native_batch_projection(
            self, rows, canonical_token=canonical_token
        )

    @property
    def publication_token(self) -> str:
        """Return the all-member completion proof for an outer canonical receipt."""
        return self._registry._batch_claim(self).proof.hex()

    @property
    def committed(self) -> bool:
        """Whether this active claim finalized every reserved counter effect."""
        return self._registry._batch_claim(self).committed

    def apply_provisional(self) -> None:
        """Apply the final counters with no prefix and roll back unless finalized."""
        self._registry._apply_claimed_batch(self)

    def finalize_no_fail(self) -> None:
        """Publish the prepared all-member completion proof."""
        self._registry._finalize_claimed_batch(self)

    def commit_no_fail(self) -> None:
        """Apply and finalize the bounded group for standalone callers."""
        self.apply_provisional()
        self.finalize_no_fail()


@dataclass(slots=True)
class _BatchClaim:
    handle: PreparedESDeliveryBatchCommit
    capability: ESDeliveryBatchPreparation
    observations: tuple[ESCollectorObservation, ...]
    after: ESCollectorState | None
    proof: bytes
    thread_id: int
    committed: bool = False
    native_projection: _NativeProjection | None = None
    before: ESCollectorState | None = None
    applied: bool = False


class PreparedESCollectorClosures:
    """Claim-scoped reversible disconnects for an outer canonical transaction."""

    __slots__ = ("_registry",)

    def __init__(self, registry: ESCollectorRegistry) -> None:
        self._registry = registry

    @property
    def expected_result(self) -> tuple[ESCollectorState, ...]:
        """Return the exact detached terminal result retained by this claim."""
        return self._registry._closure_claim(self).result

    @property
    def publication_token(self) -> str:
        """Return the authenticated terminal connection proof."""
        return self._registry._closure_claim(self).proof.hex()

    @property
    def committed(self) -> bool:
        """Whether the owning transaction finalized every disconnect."""
        return self._registry._closure_claim(self).committed

    def apply_provisional(self) -> None:
        """Install terminal snapshots while retaining rollback ownership."""
        self._registry._apply_closures(self)

    def finalize_no_fail(self) -> None:
        """Make the provisional disconnects permanent without allocating counters."""
        self._registry._finalize_closures(self)

    def commit_no_fail(self) -> None:
        """Apply and finalize all claimed disconnects for standalone callers."""
        self.apply_provisional()
        self.finalize_no_fail()


@dataclass(slots=True)
class _ClosureClaim:
    handle: PreparedESCollectorClosures
    before: tuple[ESCollectorState, ...]
    after: tuple[ESCollectorState, ...]
    result: tuple[ESCollectorState, ...]
    proof: bytes
    thread_id: int
    applied: bool = False
    committed: bool = False


def _advance_delivery(
    before: ESCollectorState,
    *,
    source_instance: str,
    generation: int,
    delivery: int,
    occurrence_id: str,
    event_type: int,
    observed_at: datetime,
    decision: ObservationDecision,
    kernel_lost: tuple[ESKernelLoss, ...],
) -> tuple[ESCollectorObservation, ESCollectorState]:
    """Compute a detached counter transition without reserving or publishing anything."""
    if (
        type(decision) is not ObservationDecision
        or type(decision.delay) is not timedelta
        or decision.delay < timedelta(0)
    ):
        raise StateError("ES delivery requires an exact nonnegative observation decision")
    if type(kernel_lost) is not tuple or any(
        type(item) is not ESKernelLoss for item in kernel_lost
    ):
        raise StateError("ES loss requires exact per-event counts")
    kernel_lost = tuple(
        ESKernelLoss(event_type=item.event_type, count=item.count) for item in kernel_lost
    )
    if (
        type(generation) is not int
        or type(delivery) is not int
        or (generation != before.generation or delivery != before.next_delivery)
    ):
        raise StateError("ES delivery requires the exact connection and next ordinal")
    counters = {item.event_type: item.next_sequence for item in before.event_counters}
    if type(event_type) is not int or event_type not in counters:
        raise StateError("ES event is not subscribed by this client")
    if (
        type(observed_at) is not datetime
        or observed_at.utcoffset() is None
        or observed_at < before.last_delivery_at
    ):
        raise StateError("ES client deliveries require chronological aware times")
    losses = {item.event_type: item.count for item in kernel_lost}
    if len(losses) != len(kernel_lost) or not losses.keys() <= counters.keys():
        raise StateError("ES loss must name distinct subscribed event types")
    for kind, count in losses.items():
        counters[kind] += count
    global_sequence = before.next_global_sequence + sum(losses.values())
    observation = ESCollectorObservation(
        source_instance=source_instance,
        hostname=before.hostname,
        generation=generation,
        delivery=delivery,
        occurrence_id=occurrence_id,
        event_type=event_type,
        observed_at=observed_at,
        collector_process=before.process,
        seq_num=counters[event_type],
        global_seq_num=global_sequence,
        status=decision.status,
        delay=decision.delay,
    )
    counters[event_type] += 1
    after = ESCollectorState(
        **(
            before.model_dump()
            | dict(
                next_delivery=delivery + 1,
                last_delivery_at=observed_at,
                next_global_sequence=global_sequence + 1,
                event_counters=tuple(
                    ESEventCounter(event_type=kind, next_sequence=count)
                    for kind, count in sorted(counters.items())
                ),
            )
        )
    )
    return observation, after


class ESCollectorRegistry:
    """Transactional source-local counters with bounded current-client state.

    Kernel loss advances the affected subscribed counters explicitly. Export
    missingness/filtering consumes one delivered event without masquerading as
    kernel loss. Output selection never participates in sequence allocation.
    Checkpoints require no pending preparation; completed retry proofs stay on
    caller-held capabilities rather than an unbounded occurrence ledger.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._states: dict[str, ESCollectorState] = {}
        self._pending: dict[str, _Pending | _PendingBatch] = {}
        self._claimed: dict[str, _DeliveryClaim | _BatchClaim] = {}
        self._closing: dict[str, _ClosureClaim] = {}
        self._secret = secrets.token_bytes(32)

    def open(self, state: ESCollectorState) -> None:
        """Install explicit initial counters or replace a quiescent prior connection."""
        if type(state) is not ESCollectorState:
            raise StateError("ES client requires an exact connection profile")
        state = ESCollectorState.model_validate_json(state.model_dump_json())
        if (
            state.closed_at is not None
            or state.next_delivery != 0
            or state.last_delivery_at != state.opened_at
        ):
            raise StateError("New ES client connection cannot contain delivered history")
        with self._lock:
            previous = self._states.get(state.source_instance)
            if (
                state.source_instance in self._pending
                or state.source_instance in self._claimed
                or state.source_instance in self._closing
            ):
                raise StateError("ES client restart requires completed publication")
            if previous is None:
                if len(self._states) >= 128 or state.generation != 1:
                    raise StateError("ES client capacity or initial generation is invalid")
            elif (
                state.hostname != previous.hostname
                or state.generation != previous.generation + 1
                or state.opened_at <= (previous.closed_at or previous.last_delivery_at)
            ):
                raise StateError("ES client restart requires the next same-host connection")
            self._states[state.source_instance] = state

    def open_connections(self) -> tuple[ESCollectorState, ...]:
        """Inspect explicit open profiles without inferring unmodeled client absence."""
        with self._lock:
            return tuple(
                ESCollectorState.model_validate_json(self._states[key].model_dump_json())
                for key in sorted(self._states)
                if self._states[key].closed_at is None
            )

    def connection(self, source_instance: str) -> ESCollectorState | None:
        """Return the immutable current connection, including its terminal state."""
        with self._lock:
            value = self._states.get(source_instance)
            return ESCollectorState.model_validate_json(value.model_dump_json()) if value else None

    def known_connection_for_process(
        self, hostname: str, process: ESCollectorProcess, observed_at: datetime
    ) -> ESCollectorState | None:
        """Return positive attachment knowledge from retained current epochs.

        None means unknown, never proof of non-membership. Replaced epochs are
        not an unbounded history. This bounded lookup works during a prepared
        delivery, unlike checkpoint capture, and never changes counters. Several
        clients may belong to one execution; source order makes selection stable.
        """
        if (
            type(hostname) is not str
            or not hostname.strip()
            or type(process) is not ESCollectorProcess
            or type(observed_at) is not datetime
            or observed_at.utcoffset() is None
        ):
            raise StateError("ES attachment lookup requires exact host, execution and time")
        process = ESCollectorProcess.model_validate_json(process.model_dump_json())
        with self._lock:
            for key in sorted(self._states):
                value = self._states[key]
                if (
                    value.hostname == hostname
                    and value.process == process
                    and value.opened_at <= observed_at
                    and (value.closed_at is None or observed_at < value.closed_at)
                ):
                    return ESCollectorState.model_validate_json(value.model_dump_json())
        return None

    def close(self, expected: ESCollectorState, closed_at: datetime) -> None:
        """Close an exact idle connection without allocating a delivery or inferring exit."""
        if (
            type(expected) is not ESCollectorState
            or type(closed_at) is not datetime
            or closed_at.utcoffset() is None
        ):
            raise StateError("Collector closure requires an exact connection and aware time")
        after = ESCollectorState.model_validate_json(
            expected.model_copy(update={"closed_at": closed_at}).model_dump_json()
        )
        with self._lock:
            current = self._states.get(expected.source_instance)
            if (
                current != expected
                or expected.source_instance in self._pending
                or expected.source_instance in self._claimed
                or expected.source_instance in self._closing
            ):
                raise StateError("Collector closure requires the unchanged idle connection")
            if current.closed_at is not None:
                if current.closed_at == closed_at:
                    return
                raise StateError("Collector closure cannot rewrite its terminal time")
            self._states[expected.source_instance] = after

    def _closure_proof(self, states: tuple[ESCollectorState, ...]) -> bytes:
        payload = bytearray(b"es-collector-closures\0")
        for state in states:
            if type(state) is not ESCollectorState:
                raise StateError("Collector closure result lost its exact terminal shape")
            encoded = state.model_dump_json().encode("utf-8")
            payload.extend(len(encoded).to_bytes(8, "big"))
            payload.extend(encoded)
        return hmac.digest(self._secret, payload, "sha256")

    @contextmanager
    def prepared_closures(
        self, requests: tuple[ESCollectorClosure, ...]
    ) -> Iterator[PreparedESCollectorClosures]:
        """Fence a bounded idle-client set; unfinalized scope exit restores all clients.

        Acquire the canonical State owner before entering this scope. This method
        supplies no process-exit inference or native evidence. Each request must
        come from the caller's exact connection and lifecycle ownership.
        """
        if (
            type(requests) is not tuple
            or not 1 <= len(requests) <= 128
            or any(type(item) is not ESCollectorClosure for item in requests)
        ):
            raise StateError("Collector closure requires 1 to 128 exact requests")
        requests = tuple(
            ESCollectorClosure.model_validate_json(item.model_dump_json()) for item in requests
        )
        keys = tuple(item.before.source_instance for item in requests)
        if len(set(keys)) != len(keys):
            raise StateError("Collector closure requires distinct connection owners")
        before = tuple(item.before for item in requests)
        after = tuple(
            ESCollectorState.model_validate_json(
                item.before.model_copy(update={"closed_at": item.closed_at}).model_dump_json()
            )
            for item in requests
        )
        result = tuple(
            ESCollectorState.model_validate_json(item.model_dump_json()) for item in after
        )
        handle = PreparedESCollectorClosures(self)
        claim = _ClosureClaim(
            handle, before, after, result, self._closure_proof(result), get_ident()
        )
        with self._lock:
            if any(
                self._states.get(key) != previous
                or key in self._pending
                or key in self._claimed
                or key in self._closing
                for key, previous in zip(keys, before, strict=True)
            ):
                raise StateError("Collector closure requires unchanged idle connections")
            try:
                for key in keys:
                    self._closing[key] = claim
                yield handle
            finally:
                if claim.applied and not claim.committed:
                    for key, previous in zip(keys, before, strict=True):
                        self._states[key] = previous
                for key in keys:
                    if self._closing.get(key) is claim:
                        del self._closing[key]

    def _closure_claim(self, handle: PreparedESCollectorClosures) -> _ClosureClaim:
        if type(handle) is not PreparedESCollectorClosures or handle._registry is not self:
            raise StateError("Collector closure requires its exact active claim")
        claim = next((item for item in self._closing.values() if item.handle is handle), None)
        if claim is None or claim.thread_id != get_ident():
            raise StateError("Collector closure requires its same-thread active claim")
        if self._closure_proof(claim.result) != claim.proof:
            raise StateError("Collector closure terminal result changed")
        expected = claim.after if claim.applied else claim.before
        if any(self._states.get(item.source_instance) != item for item in expected):
            raise StateError("Collector closure lost its exact connection snapshots")
        return claim

    def _apply_closures(self, handle: PreparedESCollectorClosures) -> None:
        claim = self._closure_claim(handle)
        if claim.applied:
            return
        claim.applied = True
        for state in claim.after:
            self._states[state.source_instance] = state

    def _finalize_closures(self, handle: PreparedESCollectorClosures) -> None:
        claim = self._closure_claim(handle)
        if not claim.applied:
            raise StateError("Collector closure finalization requires provisional application")
        claim.committed = True

    def prepare(
        self,
        *,
        source_instance: str,
        generation: int,
        delivery: int,
        occurrence_id: str,
        event_type: int,
        observed_at: datetime,
        decision: ObservationDecision,
        kernel_lost: tuple[ESKernelLoss, ...] = (),
    ) -> ESDeliveryPreparation:
        """Reserve one canonical delivery and explicit preceding kernel losses."""
        with self._lock:
            before = self._states.get(source_instance)
            if (
                before is None
                or before.closed_at is not None
                or source_instance in self._pending
                or source_instance in self._claimed
                or source_instance in self._closing
            ):
                raise StateError("ES delivery requires an open idle client")
            observation, after = _advance_delivery(
                before,
                source_instance=source_instance,
                generation=generation,
                delivery=delivery,
                occurrence_id=occurrence_id,
                event_type=event_type,
                observed_at=observed_at,
                decision=decision,
                kernel_lost=kernel_lost,
            )
            capability = ESDeliveryPreparation(
                ESCollectorObservation.model_validate_json(observation.model_dump_json())
            )
            self._pending[source_instance] = _Pending(capability, after, observation)
            return capability

    def prepare_batch(
        self,
        *,
        source_instance: str,
        generation: int,
        delivery: int,
        requests: tuple[ESDeliveryRequest, ...],
    ) -> ESDeliveryBatchPreparation:
        """Reserve an ordered bounded group without publishing a partial counter advance."""
        if (
            type(requests) is not tuple
            or not 1 <= len(requests) <= 256
            or any(type(item) is not ESDeliveryRequest for item in requests)
        ):
            raise StateError("ES batch requires 1 to 256 exact delivery requests")
        requests = tuple(
            ESDeliveryRequest.model_validate_json(item.model_dump_json()) for item in requests
        )
        with self._lock:
            before = self._states.get(source_instance)
            if (
                before is None
                or before.closed_at is not None
                or source_instance in self._pending
                or source_instance in self._claimed
                or source_instance in self._closing
            ):
                raise StateError("ES batch requires an open idle client")
            current = before
            observations: list[ESCollectorObservation] = []
            for index, request in enumerate(requests):
                observation, current = _advance_delivery(
                    current,
                    source_instance=source_instance,
                    generation=generation,
                    delivery=delivery if index == 0 else current.next_delivery,
                    occurrence_id=request.occurrence_id,
                    event_type=request.event_type,
                    observed_at=request.observed_at,
                    decision=request.decision,
                    kernel_lost=request.kernel_lost,
                )
                observations.append(observation)
            trusted = tuple(observations)
            capability = ESDeliveryBatchPreparation(
                tuple(
                    ESCollectorObservation.model_validate_json(item.model_dump_json())
                    for item in trusted
                )
            )
            self._pending[source_instance] = _PendingBatch(capability, current, trusted)
            return capability

    @staticmethod
    def _validate_batch_capability(capability: ESDeliveryBatchPreparation) -> None:
        if (
            type(capability) is not ESDeliveryBatchPreparation
            or type(capability.observations) is not tuple
            or not 1 <= len(capability.observations) <= 256
            or any(type(item) is not ESCollectorObservation for item in capability.observations)
        ):
            raise StateError("ES batch publication requires its exact bounded capability")

    def _batch_proof_for(
        self, capability: ESDeliveryBatchPreparation, native: _NativeProjection | None
    ) -> bytes:
        # A distinct domain separates this proof from the single-delivery contract.
        material = b"es-delivery-batch-v1:" + str(id(capability)).encode()
        for item in capability.observations:
            encoded = item.model_dump_json().encode()
            material += len(encoded).to_bytes(8, "big") + encoded
        if native is not None:
            material += b":native-projection:" + native.proof
        return hmac.digest(self._secret, material, hashlib.sha256)

    def _batch_proof(self, capability: ESDeliveryBatchPreparation) -> bytes:
        return self._batch_proof_for(capability, capability._native_projection)

    def completed_batch(
        self, capability: ESDeliveryBatchPreparation
    ) -> tuple[ESCollectorObservation, ...] | None:
        """Authenticate a completed group without replaying any member allocation."""
        self._validate_batch_capability(capability)
        with self._lock:
            if (
                self._native_authenticates(capability)
                and capability._proof
                and hmac.compare_digest(capability._proof, self._batch_proof(capability))
            ):
                return capability.observations
            return None

    @contextmanager
    def prepared_batch(
        self, capability: ESDeliveryBatchPreparation
    ) -> Iterator[PreparedESDeliveryBatchCommit]:
        """Hold a prevalidated batch claim for an outer State/native-source commit."""
        self._validate_batch_capability(capability)
        with self._lock:
            key = capability.observations[0].source_instance
            if key in self._claimed or key in self._closing:
                raise StateError("ES batch already has an active commit scope")
            completed = self.completed_batch(capability)
            handle = PreparedESDeliveryBatchCommit(self, key)
            if completed is not None:
                claim = _BatchClaim(
                    handle,
                    capability,
                    completed,
                    None,
                    capability._proof,
                    get_ident(),
                    native_projection=capability._native_projection,
                )
            else:
                pending = self._pending.get(key)
                if (
                    type(pending) is not _PendingBatch
                    or pending.capability is not capability
                    or pending.observations != capability.observations
                    or pending.native_projection is not capability._native_projection
                    or not self._native_authenticates(capability)
                ):
                    raise StateError("ES batch capability is stale or changed")
                claim = _BatchClaim(
                    handle,
                    capability,
                    pending.observations,
                    pending.after,
                    self._batch_proof(capability),
                    get_ident(),
                    native_projection=pending.native_projection,
                )
            claim.before = self._states.get(key) if claim.after is not None else None
            self._claimed[key] = claim
            try:
                yield handle
            finally:
                if claim.applied and not claim.committed and claim.before is not None:
                    self._states[key] = claim.before
                del self._claimed[key]

    def _batch_claim(self, handle: PreparedESDeliveryBatchCommit) -> _BatchClaim:
        if type(handle) is not PreparedESDeliveryBatchCommit:
            raise StateError("ES batch commit requires its active preparation scope")
        key = object.__getattribute__(handle, "_source_instance")
        claim = self._claimed.get(key) if type(key) is str else None
        if (
            type(claim) is not _BatchClaim
            or claim.handle is not handle
            or claim.thread_id != get_ident()
            or object.__getattribute__(handle, "_registry") is not self
        ):
            raise StateError("ES batch commit requires its active preparation scope")
        return claim

    def _apply_claimed_batch(self, handle: PreparedESDeliveryBatchCommit) -> None:
        """Install only precomputed counters; the active scope owns rollback."""
        claim = self._batch_claim(handle)
        if claim.committed or claim.applied:
            return
        if claim.after is not None:
            if claim.before is None:
                raise StateError("ES provisional counters lost their exact connection savepoint")
            self._states[claim.observations[0].source_instance] = claim.after
        claim.applied = True

    def _finalize_claimed_batch(self, handle: PreparedESDeliveryBatchCommit) -> None:
        """Finish the primitive proof tail only after provisional application."""
        claim = self._batch_claim(handle)
        if claim.committed:
            return
        if not claim.applied:
            raise StateError("ES counter finalization requires provisional application")
        if claim.after is not None:
            key = claim.observations[0].source_instance
            object.__setattr__(claim.capability, "_native_projection", claim.native_projection)
            object.__setattr__(claim.capability, "_proof", claim.proof)
            del self._pending[key]
        claim.committed = True

    def commit_batch(
        self, capability: ESDeliveryBatchPreparation
    ) -> tuple[ESCollectorObservation, ...]:
        """Commit all reserved counter effects once, including a lost-return retry."""
        with self.prepared_batch(capability) as prepared:
            prepared.commit_no_fail()
            return prepared.observations

    def owns_pending_batch(self, capability: object) -> bool:
        """Locate exact group cleanup ownership independently of mutable facts.

        At most 128 source slots are inspected. This establishes cancellation
        ownership only, never event validity or permission to publish counters.
        """
        if type(capability) is not ESDeliveryBatchPreparation:
            return False
        with self._lock:
            return any(
                type(pending) is _PendingBatch and pending.capability is capability
                for pending in self._pending.values()
            )

    def authenticates_pending_batch(self, capability: object) -> bool:
        """Whether this exact uncompleted group retains its reserved ordered facts."""
        try:
            self._validate_batch_capability(capability)
        except StateError:
            return False
        key = capability.observations[0].source_instance
        if type(key) is not str:
            return False
        with self._lock:
            pending = self._pending.get(key)
            return bool(
                type(pending) is _PendingBatch
                and pending.capability is capability
                and pending.observations == capability.observations
                and pending.native_projection is capability._native_projection
                and self._native_authenticates(capability)
            )

    def cancel_batch(self, capability: ESDeliveryBatchPreparation) -> None:
        """Cancel the exact unclaimed group without trusting its observation locator."""
        if type(capability) is not ESDeliveryBatchPreparation:
            raise StateError("ES batch cancellation requires its exact capability")
        with self._lock:
            key = next(
                (
                    source_instance
                    for source_instance, pending in self._pending.items()
                    if type(pending) is _PendingBatch and pending.capability is capability
                ),
                None,
            )
            if key is None:
                raise StateError("ES batch cancellation capability is stale")
            if key in self._claimed or key in self._closing:
                raise StateError("ES batch cancellation requires an unclaimed reservation")
            del self._pending[key]

    def _proof_for(
        self, capability: ESDeliveryPreparation, native: _NativeProjection | None
    ) -> bytes:
        material = str(id(capability)).encode() + capability.observation.model_dump_json().encode()
        if native is not None:
            material += b":native-projection:" + native.proof
        return hmac.digest(self._secret, material, hashlib.sha256)

    def _proof(self, capability: ESDeliveryPreparation) -> bytes:
        return self._proof_for(capability, capability._native_projection)

    def _native_proof(
        self,
        capability: ESDeliveryPreparation | ESDeliveryBatchPreparation,
        ndjson: str,
        canonical_token: str | None,
    ) -> bytes:
        domain = b"es-native-projection-v1:"
        if type(capability) is ESDeliveryPreparation:
            observation = capability.observation.model_dump_json().encode()
        else:
            domain = b"es-native-projection-batch-v1:"
            fields = tuple(item.model_dump_json().encode() for item in capability.observations)
            observation = b"".join(len(item).to_bytes(8, "big") + item for item in fields)
        payload = ndjson.encode("utf-8")
        canonical = b"" if canonical_token is None else canonical_token.encode("ascii")
        material = (
            domain
            + str(id(capability)).encode()
            + b":"
            + len(observation).to_bytes(8, "big")
            + observation
            + len(payload).to_bytes(8, "big")
            + payload
            + len(canonical).to_bytes(8, "big")
            + canonical
        )
        return hmac.digest(self._secret, material, hashlib.sha256)

    @staticmethod
    def _valid_native_canonical_token(token: object) -> bool:
        return token is None or (
            type(token) is str
            and len(token) == 64
            and all(character in "0123456789abcdef" for character in token)
        )

    def _native_authenticates(
        self, capability: ESDeliveryPreparation | ESDeliveryBatchPreparation
    ) -> bool:
        native = capability._native_projection
        budget = (
            _MAX_NATIVE_ROW_BYTES
            if type(capability) is ESDeliveryPreparation
            else _MAX_NATIVE_BATCH_BYTES
        )
        if native is None:
            return True
        if (
            type(native) is not _NativeProjection
            or type(native.ndjson) is not str
            or len(native.ndjson) > budget
            or type(native.proof) is not bytes
            or not self._valid_native_canonical_token(native.canonical_token)
        ):
            return False
        try:
            return hmac.compare_digest(
                native.proof, self._native_proof(capability, native.ndjson, native.canonical_token)
            )
        except UnicodeEncodeError:
            return False

    @staticmethod
    def _validate_native_line(ndjson: str) -> int:
        """Validate one source-owned line and return its bounded UTF-8 size."""
        if (
            type(ndjson) is not str
            or not ndjson.endswith("\n")
            or "\n" in ndjson[:-1]
            or "\r" in ndjson
        ):
            raise StateError("ES native projection requires one newline-terminated NDJSON line")
        if len(ndjson) > _MAX_NATIVE_ROW_BYTES:
            raise StateError("ES native projection exceeds its 1 MiB modeled row budget")
        try:
            size = len(ndjson.encode("utf-8"))
        except UnicodeEncodeError as error:
            raise StateError("ES native projection requires valid UTF-8") from error
        if not 2 <= size <= _MAX_NATIVE_ROW_BYTES:
            raise StateError("ES native projection exceeds its 1 MiB modeled row budget")
        return size

    def _freeze_native_projection(
        self, handle: PreparedESDeliveryCommit, ndjson: str, *, canonical_token: str | None
    ) -> str:
        claim = self._delivery_claim(handle)
        if not self._valid_native_canonical_token(canonical_token):
            raise StateError("ES native projection requires an exact canonical publication token")
        self._validate_native_line(ndjson)
        capability = claim.capability
        if (
            type(capability.observation) is not ESCollectorObservation
            or capability.observation != claim.observation
            or capability._native_projection is not claim.native_projection
            or not self._native_authenticates(capability)
            or not hmac.compare_digest(
                claim.proof, self._proof_for(capability, claim.native_projection)
            )
        ):
            raise StateError("ES native projection lost its exact counter observation")
        native = claim.native_projection
        if native is not None:
            if native.ndjson != ndjson or native.canonical_token != canonical_token:
                raise StateError("ES native projection changed for the same reserved delivery")
            return native.ndjson
        if claim.committed or claim.applied or claim.after is None:
            raise StateError("ES native projection must freeze before counter publication")
        pending = self._pending.get(claim.observation.source_instance)
        if type(pending) is not _Pending or pending.capability is not capability:
            raise StateError("ES native projection lost its reserved delivery")
        native = _NativeProjection(
            ndjson, canonical_token, self._native_proof(capability, ndjson, canonical_token)
        )
        replacement = replace(pending, native_projection=native)
        proof = self._proof_for(capability, native)
        self._pending[claim.observation.source_instance] = replacement
        object.__setattr__(capability, "_native_projection", native)
        claim.native_projection = native
        claim.proof = proof
        return native.ndjson

    def _freeze_native_batch_projection(
        self,
        handle: PreparedESDeliveryBatchCommit,
        rows: tuple[str, ...],
        *,
        canonical_token: str | None,
    ) -> tuple[str, ...]:
        claim = self._batch_claim(handle)
        if not self._valid_native_canonical_token(canonical_token):
            raise StateError("ES native batch requires an exact canonical publication token")
        if type(rows) is not tuple or len(rows) != len(claim.observations):
            raise StateError("ES native batch requires one exact row per reserved observation")
        total = 0
        for row in rows:
            total += self._validate_native_line(row)
            if total > _MAX_NATIVE_BATCH_BYTES:
                raise StateError("ES native batch exceeds its 16 MiB modeled budget")
        capability = claim.capability
        self._validate_batch_capability(capability)
        if (
            capability.observations != claim.observations
            or capability._native_projection is not claim.native_projection
            or not self._native_authenticates(capability)
            or not hmac.compare_digest(
                claim.proof, self._batch_proof_for(capability, claim.native_projection)
            )
        ):
            raise StateError("ES native batch lost its exact counter observations")
        rendered = "".join(rows)
        native = claim.native_projection
        if native is not None:
            if native.ndjson != rendered or native.canonical_token != canonical_token:
                raise StateError("ES native batch changed for the same reserved deliveries")
            return rows
        if claim.committed or claim.applied or claim.after is None:
            raise StateError("ES native batch must freeze before counter publication")
        key = claim.observations[0].source_instance
        pending = self._pending.get(key)
        if type(pending) is not _PendingBatch or pending.capability is not capability:
            raise StateError("ES native batch lost its reserved deliveries")
        native = _NativeProjection(
            rendered, canonical_token, self._native_proof(capability, rendered, canonical_token)
        )
        replacement = replace(pending, native_projection=native)
        proof = self._batch_proof_for(capability, native)
        self._pending[key] = replacement
        object.__setattr__(capability, "_native_projection", native)
        claim.native_projection = native
        claim.proof = proof
        return rows

    def retained_native_batch_projection(
        self, capability: ESDeliveryBatchPreparation, *, canonical_token: str | None = None
    ) -> tuple[str, ...] | None:
        """Recover the exact ordered row group without replaying or observing State."""
        self._validate_batch_capability(capability)
        if not self._valid_native_canonical_token(canonical_token):
            raise StateError("ES native batch requires an exact canonical publication token")
        with self._lock:
            pending = self._pending.get(capability.observations[0].source_instance)
            if type(pending) is _PendingBatch and pending.capability is capability:
                if (
                    pending.observations != capability.observations
                    or pending.native_projection is not capability._native_projection
                    or not self._native_authenticates(capability)
                ):
                    raise StateError("ES native batch capability changed")
            elif self.completed_batch(capability) is None:
                raise StateError("ES native batch capability is stale or foreign")
            native = capability._native_projection
            if canonical_token is not None and (
                native is None or native.canonical_token != canonical_token
            ):
                raise StateError("ES native batch belongs to another canonical publication")
            if native is None:
                return None
            # Only LF delimits NDJSON. Unicode line separators inside JSON strings
            # are valid payload and must not be split by str.splitlines().
            return tuple(row + "\n" for row in native.ndjson.split("\n")[:-1])

    def retained_native_projection(
        self, capability: ESDeliveryPreparation, *, canonical_token: str | None = None
    ) -> str | None:
        """Recover authenticated frozen bytes without re-observing canonical State.

        Works for the exact pending delivery or its completed caller-held proof,
        including after a connection restart. Cancelled and foreign capabilities
        cannot resurrect a row. No global completed-row ledger is retained.
        """
        if (
            type(capability) is not ESDeliveryPreparation
            or type(capability.observation) is not ESCollectorObservation
        ):
            raise StateError("ES native projection requires its exact delivery capability")
        if not self._valid_native_canonical_token(canonical_token):
            raise StateError("ES native projection requires an exact canonical publication token")
        with self._lock:
            pending = self._pending.get(capability.observation.source_instance)
            if type(pending) is _Pending and pending.capability is capability:
                if (
                    pending.observation != capability.observation
                    or pending.native_projection is not capability._native_projection
                    or not self._native_authenticates(capability)
                ):
                    raise StateError("ES native projection capability changed")
            elif self.completed_observation(capability) is None:
                raise StateError("ES native projection capability is stale or foreign")
            native = capability._native_projection
            if canonical_token is not None and (
                native is None or native.canonical_token != canonical_token
            ):
                raise StateError("ES native projection belongs to another canonical publication")
            return None if native is None else native.ndjson

    def owns_pending_delivery(self, capability: object) -> bool:
        """Locate cleanup ownership even when caller-held observation fields changed.

        This does not authenticate event facts or authorize publication. At most
        128 source slots are inspected; only the exact reserved object can match.
        """
        if type(capability) is not ESDeliveryPreparation:
            return False
        with self._lock:
            return any(
                type(pending) is _Pending and pending.capability is capability
                for pending in self._pending.values()
            )

    def authenticates_pending_delivery(self, capability: object) -> bool:
        """Whether this exact uncompleted capability still owns its reservation."""
        if (
            type(capability) is not ESDeliveryPreparation
            or type(capability.observation) is not ESCollectorObservation
        ):
            return False
        with self._lock:
            pending = self._pending.get(capability.observation.source_instance)
            return bool(
                type(pending) is _Pending
                and pending.capability is capability
                and pending.observation == capability.observation
                and pending.native_projection is capability._native_projection
                and self._native_authenticates(capability)
            )

    def completed_observation(
        self, capability: ESDeliveryPreparation
    ) -> ESCollectorObservation | None:
        """Authenticate an already completed observation without advancing counters."""
        if (
            type(capability) is not ESDeliveryPreparation
            or type(capability.observation) is not ESCollectorObservation
        ):
            raise StateError("ES completion lookup requires its exact capability")
        with self._lock:
            if (
                self._native_authenticates(capability)
                and capability._proof
                and hmac.compare_digest(capability._proof, self._proof(capability))
            ):
                return capability.observation
            return None

    @contextmanager
    def prepared_delivery(
        self, capability: ESDeliveryPreparation
    ) -> Iterator[PreparedESDeliveryCommit]:
        """Prevalidate and retain the collector lock for a composite's final commit.

        This is a counter transaction component, not a sink or State commit.
        The outer owner must acquire State before this registry, prepare all
        fallible work first, and invoke commit_no_fail only at its commit point.
        """
        if (
            type(capability) is not ESDeliveryPreparation
            or type(capability.observation) is not ESCollectorObservation
        ):
            raise StateError("ES publication requires its exact capability")
        with self._lock:
            key = capability.observation.source_instance
            if key in self._claimed or key in self._closing:
                raise StateError("ES delivery already has an active commit scope")
            completed = self.completed_observation(capability)
            prepared = PreparedESDeliveryCommit(self, key)
            if completed is not None:
                claim = _DeliveryClaim(
                    prepared,
                    capability,
                    completed,
                    None,
                    capability._proof,
                    get_ident(),
                    native_projection=capability._native_projection,
                )
            else:
                pending = self._pending.get(key)
                if (
                    type(pending) is not _Pending
                    or pending.capability is not capability
                    or pending.observation != capability.observation
                    or pending.native_projection is not capability._native_projection
                    or not self._native_authenticates(capability)
                ):
                    raise StateError("ES publication capability is stale or changed")
                proof = self._proof(capability)
                claim = _DeliveryClaim(
                    prepared,
                    capability,
                    pending.observation,
                    pending.after,
                    proof,
                    get_ident(),
                    native_projection=pending.native_projection,
                )
            claim.before = self._states.get(key) if claim.after is not None else None
            self._claimed[key] = claim
            try:
                yield prepared
            finally:
                if claim.applied and not claim.committed and claim.before is not None:
                    self._states[key] = claim.before
                del self._claimed[key]

    def _delivery_claim(self, handle: PreparedESDeliveryCommit) -> _DeliveryClaim:
        """Authenticate an exact same-thread active handle without invoking value protocols."""
        if type(handle) is not PreparedESDeliveryCommit:
            raise StateError("ES counter commit requires its active preparation scope")
        key = object.__getattribute__(handle, "_source_instance")
        claim = self._claimed.get(key) if type(key) is str else None
        if (
            claim is None
            or claim.handle is not handle
            or claim.thread_id != get_ident()
            or object.__getattribute__(handle, "_registry") is not self
        ):
            raise StateError("ES counter commit requires its active preparation scope")
        return claim

    def _apply_claimed_delivery(self, handle: PreparedESDeliveryCommit) -> None:
        """Install only precomputed counters; the active scope owns rollback."""
        claim = self._delivery_claim(handle)
        if claim.committed or claim.applied:
            return
        if claim.after is not None:
            if claim.before is None:
                raise StateError("ES provisional counters lost their exact connection savepoint")
            self._states[claim.observation.source_instance] = claim.after
        claim.applied = True

    def _finalize_claimed_delivery(self, handle: PreparedESDeliveryCommit) -> None:
        """Finish the primitive proof tail only after provisional application."""
        claim = self._delivery_claim(handle)
        if claim.committed:
            return
        if not claim.applied:
            raise StateError("ES counter finalization requires provisional application")
        if claim.after is not None:
            key = claim.observation.source_instance
            object.__setattr__(claim.capability, "_native_projection", claim.native_projection)
            object.__setattr__(claim.capability, "_proof", claim.proof)
            del self._pending[key]
        claim.committed = True

    def commit(self, capability: ESDeliveryPreparation) -> ESCollectorObservation:
        """Advance once; retry a proven completed publication without allocating again."""
        with self.prepared_delivery(capability) as prepared:
            prepared.commit_no_fail()
            return prepared.observation

    def cancel(self, capability: ESDeliveryPreparation) -> None:
        """Release only an exact uncommitted reservation."""
        if type(capability) is not ESDeliveryPreparation:
            raise StateError("ES cancellation requires its exact capability")
        with self._lock:
            # Cancellation owns the original reservation, not the caller's mutable
            # observation locator. A changed field must not strand a source slot.
            key = next(
                (
                    source_instance
                    for source_instance, pending in self._pending.items()
                    if type(pending) is _Pending and pending.capability is capability
                ),
                None,
            )
            if key is None:
                raise StateError("ES cancellation capability is stale")
            if key in self._claimed or key in self._closing:
                raise StateError("ES cancellation requires an unclaimed reservation")
            del self._pending[key]

    def snapshot(self) -> tuple[ESCollectorState, ...]:
        """Capture quiescent source state in deterministic instance order."""
        with self._lock:
            if self._pending or self._claimed or self._closing:
                raise StateError("ES checkpoint requires completed or cancelled publication")
            return tuple(
                ESCollectorState.model_validate_json(self._states[key].model_dump_json())
                for key in sorted(self._states)
            )

    def restore(self, states: tuple[ESCollectorState, ...]) -> None:
        """Validate all client state before replacing a fresh registry."""
        if (
            type(states) is not tuple
            or len(states) > 128
            or any(type(state) is not ESCollectorState for state in states)
        ):
            raise StateError("ES checkpoint has invalid client state")
        restored = tuple(
            ESCollectorState.model_validate_json(state.model_dump_json()) for state in states
        )
        keys = tuple(state.source_instance for state in restored)
        if keys != tuple(sorted(set(keys))):
            raise StateError("ES checkpoint clients must be unique and sorted")
        with self._lock:
            if self._states or self._pending or self._claimed or self._closing:
                raise StateError("ES checkpoint requires a fresh collector registry")
            self._states = {state.source_instance: state for state in restored}
