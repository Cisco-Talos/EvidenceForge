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
from dataclasses import dataclass
from datetime import datetime, timedelta
from threading import RLock, get_ident
from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from evidenceforge.events.observation import ObservationDecision
from evidenceforge.models.exceptions import StateError

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


@dataclass(frozen=True, slots=True, eq=False)
class ESDeliveryPreparation:
    """Exact caller-held capability; terminal proof survives a lost commit return."""

    observation: ESCollectorObservation
    _proof: bytes = b""


@dataclass(frozen=True, slots=True)
class _Pending:
    capability: ESDeliveryPreparation
    after: ESCollectorState
    observation: ESCollectorObservation


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

    def commit_no_fail(self) -> None:
        """Publish the prevalidated registry-owned state under retained owner locks."""
        self._registry._commit_claimed_delivery(self)


@dataclass(slots=True)
class _DeliveryClaim:
    handle: PreparedESDeliveryCommit
    capability: ESDeliveryPreparation
    observation: ESCollectorObservation
    after: ESCollectorState | None
    proof: bytes
    thread_id: int
    committed: bool = False


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
        self._pending: dict[str, _Pending] = {}
        self._claimed: dict[str, _DeliveryClaim] = {}
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
            if state.source_instance in self._pending or state.source_instance in self._claimed:
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

    def connection(self, source_instance: str) -> ESCollectorState | None:
        """Return the immutable current connection, including its terminal state."""
        with self._lock:
            value = self._states.get(source_instance)
            return ESCollectorState.model_validate_json(value.model_dump_json()) if value else None

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
            ):
                raise StateError("Collector closure requires the unchanged idle connection")
            if current.closed_at is not None:
                if current.closed_at == closed_at:
                    return
                raise StateError("Collector closure cannot rewrite its terminal time")
            self._states[expected.source_instance] = after

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
        with self._lock:
            before = self._states.get(source_instance)
            if (
                before is None
                or before.closed_at is not None
                or source_instance in self._pending
                or source_instance in self._claimed
            ):
                raise StateError("ES delivery requires an open idle client")
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
            capability = ESDeliveryPreparation(
                ESCollectorObservation.model_validate_json(observation.model_dump_json())
            )
            self._pending[source_instance] = _Pending(capability, after, observation)
            return capability

    def _proof(self, capability: ESDeliveryPreparation) -> bytes:
        material = str(id(capability)).encode() + capability.observation.model_dump_json().encode()
        return hmac.digest(self._secret, material, hashlib.sha256)

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
            if capability._proof and hmac.compare_digest(
                capability._proof, self._proof(capability)
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
            if key in self._claimed:
                raise StateError("ES delivery already has an active commit scope")
            completed = self.completed_observation(capability)
            prepared = PreparedESDeliveryCommit(self, key)
            if completed is not None:
                claim = _DeliveryClaim(
                    prepared, capability, completed, None, capability._proof, get_ident()
                )
            else:
                pending = self._pending.get(key)
                if (
                    pending is None
                    or pending.capability is not capability
                    or pending.observation != capability.observation
                ):
                    raise StateError("ES publication capability is stale or changed")
                proof = self._proof(capability)
                claim = _DeliveryClaim(
                    prepared, capability, pending.observation, pending.after, proof, get_ident()
                )
            self._claimed[key] = claim
            try:
                yield prepared
            finally:
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

    def _commit_claimed_delivery(self, handle: PreparedESDeliveryCommit) -> None:
        """Perform only prepared dictionary/proof writes at the composite commit point."""
        claim = self._delivery_claim(handle)
        if claim.committed:
            return
        if claim.after is not None:
            key = claim.observation.source_instance
            self._states[key] = claim.after
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
            key = capability.observation.source_instance
            if key in self._claimed:
                raise StateError("ES cancellation requires an unclaimed reservation")
            pending = self._pending.get(key)
            if pending is None or pending.capability is not capability:
                raise StateError("ES cancellation capability is stale")
            del self._pending[key]

    def snapshot(self) -> tuple[ESCollectorState, ...]:
        """Capture quiescent source state in deterministic instance order."""
        with self._lock:
            if self._pending or self._claimed:
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
            if self._states or self._pending or self._claimed:
                raise StateError("ES checkpoint requires a fresh collector registry")
            self._states = {state.source_instance: state for state in restored}
