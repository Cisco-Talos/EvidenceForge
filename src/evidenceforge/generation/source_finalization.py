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

"""Caller-owned terminal source finalization and bounded exact publication."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock
from typing import Protocol, runtime_checkable

from evidenceforge.generation.emitters.base import (
    ExactPublicationAuthority,
    ExactPublicationAuthorityCensus,
    ExactPublicationBatch,
    ExactPublicationError,
)
from evidenceforge.models.exceptions import GenerationError


class SourceFinalizationError(GenerationError):
    """A terminal source cohort could not be sealed or published exactly."""


class SourceFinalizationEpoch:
    """Opaque marker retained by the caller until one source reaches terminal close."""

    __slots__ = ()


@runtime_checkable
class SourceFinalizationParticipant(Protocol):
    """Minimal terminal source lifecycle implemented by cohort-owning emitters."""

    def quiesce_source_finalization(self) -> None:
        """Reject late input and drain all admitted candidate work."""

    def seal_source_finalization(self) -> SourceFinalizationEpoch:
        """Freeze one complete source cohort into immutable private storage."""

    def publish_source_finalization(
        self,
        epoch: SourceFinalizationEpoch,
        publisher: ExactChunkPublisher,
    ) -> None:
        """Publish every sealed chunk and durably checkpoint its progress."""


class ExactStringWriter(Protocol):
    """Existing final writer boundary consumed inside exact batch preparation."""

    def write(self, rendered: str) -> None:
        """Stage or write one already-final source-native string."""


@dataclass(frozen=True, slots=True)
class ExactSourceRow:
    """One immutable final string and its already-resolved physical writer."""

    writer: ExactStringWriter
    content: str


@dataclass(frozen=True, slots=True)
class ExactChunkPublisherCensus:
    """Constant-time terminal publisher state."""

    active_child: int
    committed_child: int
    checkpointed_child: int
    row_capacity: int
    byte_capacity: int
    route_capacity: int
    high_water_rows: int
    high_water_bytes: int
    high_water_routes: int


@dataclass(slots=True)
class _ActiveChunk:
    """One strongly retained child across commit/checkpoint/release reentry."""

    epoch: SourceFinalizationEpoch
    chunk_id: int
    rows: tuple[ExactSourceRow, ...]
    batch: ExactPublicationBatch
    is_checkpointed: Callable[[], bool]
    checkpoint: Callable[[], None]
    committed: bool = False
    checkpointed: bool = False


class ExactChunkPublisher:
    """Publish one bounded exact child at a time through an unchanged core authority."""

    def __init__(
        self,
        authority: ExactPublicationAuthority,
        *,
        row_capacity: int = 512,
        byte_capacity: int = 16 * 1024 * 1024,
        route_capacity: int = 128,
    ) -> None:
        for value, label in (
            (row_capacity, "row"),
            (byte_capacity, "byte"),
            (route_capacity, "route"),
        ):
            if type(value) is not int or value <= 0:
                raise ValueError(
                    f"Exact source-finalization {label} capacity must be a positive exact int"
                )
        self._authority = authority
        self._row_capacity = row_capacity
        self._byte_capacity = byte_capacity
        self._route_capacity = route_capacity
        self._lock = Lock()
        self._operation_lock = Lock()
        self._active: _ActiveChunk | None = None
        self._high_water_rows = 0
        self._high_water_bytes = 0
        self._high_water_routes = 0

    @staticmethod
    def _encoded_size(content: str) -> int:
        if type(content) is not str:
            raise SourceFinalizationError("Exact source rows must retain one exact str")
        return len(content.encode("utf-8"))

    def _validate_rows(
        self,
        rows: tuple[ExactSourceRow, ...],
    ) -> tuple[int, int]:
        if type(rows) is not tuple or not rows:
            raise SourceFinalizationError("Exact source chunks require a nonempty exact tuple")
        if len(rows) > self._row_capacity:
            raise SourceFinalizationError("Exact source chunk row capacity is exhausted")
        retained_bytes = 0
        route_ids: set[int] = set()
        for row in rows:
            if type(row) is not ExactSourceRow:
                raise SourceFinalizationError("Exact source chunks require exact row values")
            writer = row.writer
            write = getattr(writer, "write", None)
            if not callable(write):
                raise SourceFinalizationError("Exact source row lost its final writer")
            retained_bytes += self._encoded_size(row.content)
            if retained_bytes > self._byte_capacity:
                raise SourceFinalizationError("Exact source chunk byte capacity is exhausted")
            route_ids.add(id(writer))
            if len(route_ids) > self._route_capacity:
                raise SourceFinalizationError("Exact source chunk route capacity is exhausted")
        return retained_bytes, len(route_ids)

    @staticmethod
    def _prepare_rows(rows: tuple[ExactSourceRow, ...], chunk_id: int) -> int:
        for row in rows:
            row.writer.write(row.content)
        return chunk_id

    def publish_chunk(
        self,
        epoch: SourceFinalizationEpoch,
        chunk_id: int,
        rows: tuple[ExactSourceRow, ...],
        *,
        is_checkpointed: Callable[[], bool],
        checkpoint: Callable[[], None],
    ) -> None:
        """Publish and checkpoint one immutable child, retaining it across lost returns."""

        if not isinstance(epoch, SourceFinalizationEpoch):
            raise SourceFinalizationError("Exact source chunk has a foreign epoch")
        if type(chunk_id) is not int or chunk_id < 0:
            raise SourceFinalizationError("Exact source chunk ID must be a nonnegative exact int")
        if not callable(is_checkpointed) or not callable(checkpoint):
            raise SourceFinalizationError("Exact source chunk lost its checkpoint callbacks")

        with self._lock:
            active = self._active
            if active is None:
                retained_bytes, routes = self._validate_rows(rows)
                active = _ActiveChunk(
                    epoch=epoch,
                    chunk_id=chunk_id,
                    rows=rows,
                    batch=self._authority.issue_batch(),
                    is_checkpointed=is_checkpointed,
                    checkpoint=checkpoint,
                )
                self._active = active
                self._high_water_rows = max(self._high_water_rows, len(rows))
                self._high_water_bytes = max(self._high_water_bytes, retained_bytes)
                self._high_water_routes = max(self._high_water_routes, routes)
            elif active.epoch is not epoch or active.chunk_id != chunk_id:
                raise SourceFinalizationError(
                    "Exact source publisher must finish its retained child before the next chunk"
                )

        self._resume_active(active)

    def resume(self, epoch: SourceFinalizationEpoch) -> None:
        """Complete a retained child before its source consults the next journal cursor."""

        with self._lock:
            active = self._active
        if active is None:
            return
        if active.epoch is not epoch:
            raise SourceFinalizationError("Exact source publisher retained a different epoch")
        self._resume_active(active)

    def _resume_active(self, active: _ActiveChunk) -> None:
        """Run prepare/commit, durable source checkpoint, then receipt release."""

        if not self._operation_lock.acquire(blocking=False):
            raise SourceFinalizationError(
                "Exact source publisher already has an active owner operation"
            )
        try:
            batch_state = active.batch.state
            if batch_state == "issued":
                distinct_writers = tuple(dict.fromkeys(row.writer for row in active.rows))
                active.batch.reserve_participants(distinct_writers)
                active.batch.prepare(lambda: self._prepare_rows(active.rows, active.chunk_id))
                batch_state = active.batch.state
            if batch_state not in {"committed", "releasing", "released"}:
                active.batch.commit()
                batch_state = active.batch.state
            active.committed = batch_state in {"committed", "releasing", "released"}

            if not active.checkpointed:
                if active.is_checkpointed():
                    active.checkpointed = True
                else:
                    active.checkpoint()
                    if not active.is_checkpointed():
                        raise SourceFinalizationError(
                            "Exact source chunk checkpoint was not durable"
                        )
                    active.checkpointed = True

            if batch_state == "released":
                if not active.is_checkpointed():
                    raise SourceFinalizationError(
                        "Released exact source child lost its durable checkpoint"
                    )
            else:
                active.batch.release_no_fail()
        except ExactPublicationError as error:
            raise SourceFinalizationError("Exact source chunk publication failed") from error
        finally:
            self._operation_lock.release()

        with self._lock:
            if self._active is not active:
                raise SourceFinalizationError("Exact source publisher child changed concurrently")
            if not active.batch.released or not active.checkpointed:
                raise SourceFinalizationError("Exact source publisher lost terminal child state")
            self._active = None
        active.rows = ()

    def census(self) -> ExactChunkPublisherCensus:
        """Return constant-time active child and configured bound counts."""

        with self._lock:
            active = self._active
            return ExactChunkPublisherCensus(
                active_child=int(active is not None),
                committed_child=int(active is not None and active.committed),
                checkpointed_child=int(active is not None and active.checkpointed),
                row_capacity=self._row_capacity,
                byte_capacity=self._byte_capacity,
                route_capacity=self._route_capacity,
                high_water_rows=self._high_water_rows,
                high_water_bytes=self._high_water_bytes,
                high_water_routes=self._high_water_routes,
            )


class SourceFinalizationCoordinator:
    """Retain terminal source epochs and drive their exact publication once."""

    def __init__(
        self,
        participants: tuple[SourceFinalizationParticipant, ...],
        authority: ExactPublicationAuthority,
    ) -> None:
        if type(participants) is not tuple:
            raise TypeError("Source-finalization participants must be one exact tuple")
        if any(
            not isinstance(participant, SourceFinalizationParticipant)
            for participant in participants
        ):
            raise TypeError("Source-finalization participant lost its minimal protocol")
        self._participants = participants
        self._authority = authority
        self._publisher = ExactChunkPublisher(authority)
        self._operation_lock = Lock()
        self._quiesced = 0
        self._epochs: list[SourceFinalizationEpoch] = []
        self._published = 0
        self._closed = False

    def finalize(self) -> None:
        """Quiesce, seal, and publish every source while retaining retry state."""

        if not self._operation_lock.acquire(blocking=False):
            raise SourceFinalizationError("Source-finalization coordinator already has an owner")
        try:
            while self._quiesced < len(self._participants):
                self._participants[self._quiesced].quiesce_source_finalization()
                self._quiesced += 1

            while len(self._epochs) < len(self._participants):
                participant = self._participants[len(self._epochs)]
                epoch = participant.seal_source_finalization()
                if not isinstance(epoch, SourceFinalizationEpoch):
                    raise SourceFinalizationError("Source participant returned a foreign epoch")
                self._epochs.append(epoch)

            while self._published < len(self._participants):
                participant = self._participants[self._published]
                epoch = self._epochs[self._published]
                participant.publish_source_finalization(epoch, self._publisher)
                self._published += 1

            census = self._publisher.census()
            authority_census = self._authority_census()
            if census.active_child or any(
                (
                    authority_census.active_batches,
                    authority_census.prepared_batches,
                    authority_census.retained_rows,
                    authority_census.retained_bytes,
                )
            ):
                raise SourceFinalizationError(
                    "Terminal source publication retained an active child"
                )
        finally:
            self._operation_lock.release()

    def mark_closed(self) -> None:
        """Record the fourth lifecycle operation after participant footer cleanup."""

        if not self._operation_lock.acquire(blocking=False):
            raise SourceFinalizationError("Source-finalization coordinator already has an owner")
        try:
            if self._published != len(self._participants):
                raise SourceFinalizationError("Source participants cannot close before publication")
            census = self._authority_census()
            if any(
                (
                    census.active_batches,
                    census.prepared_batches,
                    census.retained_rows,
                    census.retained_bytes,
                )
            ):
                raise SourceFinalizationError("Source close retained exact publication authority")
            self._closed = True
        finally:
            self._operation_lock.release()

    def _authority_census(self) -> ExactPublicationAuthorityCensus:
        return self._authority.census()

    @property
    def complete(self) -> bool:
        """Return whether every retained epoch reached terminal publication."""

        return self._closed

    @property
    def publication_complete(self) -> bool:
        """Return whether every retained epoch reached terminal publication."""

        return self._published == len(self._participants)

    @property
    def publisher(self) -> ExactChunkPublisher:
        """Return the engine-owned bounded publisher for diagnostics and tests."""

        return self._publisher
